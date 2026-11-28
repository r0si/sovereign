package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/config"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/server/middleware"
)

func newLoginTestServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.DefaultConfig()
	cfg.Server.JWTSecret = "test-jwt-secret-for-login"
	// Tests exercise login over plain HTTP; TLS-gating is covered by the
	// dedicated RequireTLSForAuth tests (see handlers_auth_session_test.go).
	cfg.Server.RequireTLSForAuth = false
	if err := middleware.InitJWTSecret(cfg, ""); err != nil {
		t.Fatalf("InitJWTSecret() error = %v", err)
	}
	// Mirror production startup (InitCSRFSecret runs before serving): login
	// now fails closed without the binding key.
	cfg.Crypto.CsrfKey = strings.Repeat("cd", 32) // 64 hex chars = 32 bytes
	if err := middleware.InitCSRFSecret(cfg); err != nil {
		t.Fatalf("InitCSRFSecret() error = %v", err)
	}
	return &Server{
		db:           newContractDB(t),
		cfg:          cfg,
		loginLockout: newLoginLockoutTracker(),
	}
}

func TestHandleLogin_MissingCredentials(t *testing.T) {
	s := newLoginTestServer(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/login", nil)
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.handleLogin(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v; body=%s", err, w.Body.String())
	}
	errVal, ok := resp["Error"]
	if !ok {
		errVal, ok = resp["error"]
	}
	if !ok || errVal == nil || errVal == "" {
		t.Fatalf("expected error in response body, got: %s", w.Body.String())
	}
}

func TestHandleLogin_UserNotFound(t *testing.T) {
	s := newLoginTestServer(t)

	form := url.Values{}
	form.Set("username", "nonexistent_user")
	form.Set("password", "some_password")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.handleLogin(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v; body=%s", err, w.Body.String())
	}
	errVal, ok := resp["Error"]
	if !ok {
		errVal, ok = resp["error"]
	}
	if !ok || errVal == nil || errVal == "" {
		t.Fatalf("expected error in response body, got: %s", w.Body.String())
	}
}

func TestHandleLogin_Success(t *testing.T) {
	s := newLoginTestServer(t)

	hash, err := middleware.HashPassword("correct_password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := db.User{
		Username:     "admin_user",
		PasswordHash: hash,
		Role:         "admin",
		IsActive:     true,
	}
	if err := s.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	form := url.Values{}
	form.Set("username", "admin_user")
	form.Set("password", "correct_password")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", s.handleLogin)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d; body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc != "/" {
		t.Fatalf("expected redirect to /, got %q", loc)
	}

	var updated db.User
	if err := s.db.Where("username = ?", "admin_user").First(&updated).Error; err != nil {
		t.Fatalf("user not found after login: %v", err)
	}
	if updated.LastLogin.IsZero() {
		t.Fatal("expected LastLogin to be set after successful login")
	}
}

// TestHandleLogin_SetsSessionBoundCsrfCookie proves a successful login seeds
// the double-submit CSRF cookie bound to the issued session (fail-closed
// invariant: no session may exist without its CSRF counterpart).
func TestHandleLogin_SetsSessionBoundCsrfCookie(t *testing.T) {
	s := newLoginTestServer(t)

	hash, err := middleware.HashPassword("correct_password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := s.db.Create(&db.User{Username: "csrf_user", PasswordHash: hash, Role: "admin", IsActive: true}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	form := url.Values{}
	form.Set("username", "csrf_user")
	form.Set("password", "correct_password")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", s.handleLogin)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d; body=%s", w.Code, w.Body.String())
	}
	var session, csrf string
	for _, ck := range w.Result().Cookies() {
		switch ck.Name {
		case "sovereign_session":
			session = ck.Value
		case "sovereign_csrf":
			csrf = ck.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatalf("missing cookies: session=%q csrf=%q", session, csrf)
	}
	if want := middleware.DeriveCSRFToken(session, middleware.GetCSRFSecret()); want != csrf {
		t.Fatal("CSRF cookie is not bound to the issued session")
	}
}

func TestHandleLogin_InactiveUser(t *testing.T) {
	s := newLoginTestServer(t)

	hash, err := middleware.HashPassword("pass1234")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := db.User{
		Username:     "inactive_user",
		PasswordHash: hash,
		Role:         "user",
		IsActive:     false,
	}
	if err := s.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	form := url.Values{}
	form.Set("username", "inactive_user")
	form.Set("password", "pass1234")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.handleLogin(c)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body=%s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json: %v; body=%s", err, w.Body.String())
	}
	errVal, ok := resp["Error"]
	if !ok {
		errVal, ok = resp["error"]
	}
	if !ok || errVal == nil || errVal == "" {
		t.Fatalf("expected error in response body, got: %s", w.Body.String())
	}
}

func TestHandleLoginRejectsCrossSiteOrigin(t *testing.T) {
	s := newLoginTestServer(t)
	router := gin.New()
	router.POST("/login", s.handleLogin)
	for _, tc := range []struct {
		name   string
		origin string
		want   int
	}{
		{name: "cross site", origin: "https://evil.example", want: http.StatusForbidden},
		{name: "same site", origin: "http://example.com", want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader("username=x&password=y"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tc.origin)
			router.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
