package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	forgecrypto "github.com/r0si/sovereign/internal/crypto"
	"github.com/r0si/sovereign/internal/db"
	"gorm.io/gorm"
)

func seedMaintenancePurgeRows(t *testing.T, s *Server) {
	forgecrypto.InitLootEncryption(testStorageKeyHex)
	t.Helper()
	old := time.Now().AddDate(0, 0, -4000)
	rows := []interface{}{
		&db.BuildLog{Platform: "linux", Format: "elf", Status: "success", CreatedAt: old},
		&db.Task{AgentID: "purge-agent", Type: "ps", Status: "completed", CreatedAt: old},
		&db.ChatMessage{TenantID: 1, Username: "u", Message: "old", CreatedAt: old},
	}
	for _, row := range rows {
		if err := s.db.Create(row).Error; err != nil {
			t.Fatalf("seed maintenance row: %v", err)
		}
	}
}

func maintenancePurgeContext(s *Server, tenantID uint) (*Server, *gin.Context, *httptest.ResponseRecorder) {
	c, w := globalAdminTestContext(tenantID, false)
	c.Request = httptest.NewRequest(http.MethodPost, "/settings/maintenance/purge", strings.NewReader(url.Values{}.Encode()))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s, c, w
}

func TestMaintenancePurgeDeletesOldRows(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	seedMaintenancePurgeRows(t, s)
	_, c, w := maintenancePurgeContext(s, 0)
	s.handleSettingsMaintenancePurge(c)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	for _, model := range []interface{}{&db.BuildLog{}, &db.Task{}, &db.ChatMessage{}} {
		var count int64
		if err := s.db.Model(model).Count(&count).Error; err != nil {
			t.Fatalf("count after purge: %v", err)
		}
		if count != 0 {
			t.Fatalf("%T rows remain after purge: %d", model, count)
		}
	}
}

func TestMaintenancePurgeRollsBackOnDeleteFailure(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	seedMaintenancePurgeRows(t, s)
	if err := s.db.Callback().Delete().Before("gorm:delete").Register("test:fail_chat_purge", func(tx *gorm.DB) {
		if tx.Statement.Table == "chat_messages" {
			tx.AddError(errors.New("injected delete failure"))
		}
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}

	_, c, w := maintenancePurgeContext(s, 0)
	s.handleSettingsMaintenancePurge(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	for _, model := range []interface{}{&db.BuildLog{}, &db.Task{}, &db.ChatMessage{}} {
		var count int64
		if err := s.db.Model(model).Count(&count).Error; err != nil {
			t.Fatalf("count after rollback: %v", err)
		}
		if count != 1 {
			t.Fatalf("%T rows after rollback = %d, want 1", model, count)
		}
	}
	var markers int64
	if err := s.db.Model(&db.AuditLog{}).Where("action = ?", "maintenance_purge").Count(&markers).Error; err != nil {
		t.Fatalf("count markers: %v", err)
	}
	if markers != 0 {
		t.Fatal("failed maintenance purge wrote a success audit marker")
	}
}

func TestMaintenancePurgeRejectsTenantAdmin(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	seedMaintenancePurgeRows(t, s)
	_, c, w := maintenancePurgeContext(s, 1)
	s.handleSettingsMaintenancePurge(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.db.Model(&db.Task{}).Count(&count).Error; err != nil {
		t.Fatalf("count tasks: %v", err)
	}
	if count != 1 {
		t.Fatal("tenant admin changed global maintenance data")
	}
}
