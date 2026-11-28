package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/server/middleware"
	"github.com/r0si/sovereign/internal/testutil"
)

func globalAdminTestContext(tenantID uint, scoped bool) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/global", nil)
	c.Set("user_role", db.RoleAdmin)
	c.Set("user_id", uint(1))
	c.Set(middleware.TenantIDContextKey, tenantID)
	if scoped {
		c.Set("auth_via_api_key", true)
		c.Set("api_key_scopes", map[string]bool{db.PermSettingsWrite: true})
	}
	return c, w
}

func TestGlobalAdminBoundary(t *testing.T) {
	ginSetTestMode(t)
	s := &Server{db: testutil.SetupTestDB(t)}

	for _, tc := range []struct {
		name    string
		tenant  uint
		scoped  bool
		allowed bool
	}{
		{name: "global admin", tenant: 0, allowed: true},
		{name: "tenant admin", tenant: 1},
		{name: "scoped global admin", tenant: 0, scoped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, w := globalAdminTestContext(tc.tenant, tc.scoped)
			if got := s.requireGlobalAdmin(c); got != tc.allowed {
				t.Fatalf("requireGlobalAdmin = %v, want %v; body=%s", got, tc.allowed, w.Body.String())
			}
		})
	}
}

func TestScopedAPIKeyCannotUseAdminBranches(t *testing.T) {
	ginSetTestMode(t)
	s := &Server{db: testutil.SetupTestDB(t)}
	c, _ := globalAdminTestContext(0, true)

	if s.requireAdmin(c) {
		t.Fatal("scoped API key satisfied requireAdmin")
	}
	if s.isAdmin(c) {
		t.Fatal("scoped API key satisfied isAdmin")
	}
	if s.keyCreatorMayGrant(c, db.PermSettingsWrite) {
		t.Fatal("scoped API key reached the admin key-grant branch")
	}
}

func TestGlobalAdminMiddlewareAbortsTenantAdmin(t *testing.T) {
	ginSetTestMode(t)
	s := &Server{db: testutil.SetupTestDB(t)}
	engine := gin.New()
	engine.GET("/global", func(c *gin.Context) {
		c.Set("user_role", db.RoleAdmin)
		c.Set("user_id", uint(1))
		c.Set(middleware.TenantIDContextKey, uint(1))
		c.Next()
	}, s.globalAdminOnly(), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/global", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant admin status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
