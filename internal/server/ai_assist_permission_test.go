package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
)

func aiAssistPermissionEngine(s *Server, permissions map[string]bool) *gin.Engine {
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("user", "custom")
		c.Set("user_role", "custom")
		c.Set("user_id", uint(1))
		c.Set("tenant_id", uint(1))
		c.Set("role_permissions", permissions)
		c.Next()
	})
	s.registerAgentRoutes(engine.Group(""))
	return engine
}

func TestAIAssistRoutesRequireAIUse(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	engine := aiAssistPermissionEngine(s, map[string]bool{db.PermAgentsRead: true})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/ai/analyze-result", strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("agents.read status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func TestAIAssistTaskReadsRequireTasksRead(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	engine := aiAssistPermissionEngine(s, map[string]bool{db.PermAIUse: true})
	for _, path := range []string{"/api/ai/pending-tasks", "/api/ai/nl-query"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if path == "/api/ai/nl-query" {
			req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"question":"show tasks"}`))
			req.Header.Set("Content-Type", "application/json")
		}
		engine.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403; body=%s", path, w.Code, w.Body.String())
		}
	}
}
