package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
)

func TestNotificationsAndRoutesAreTenantScoped(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	own := db.Notification{TenantID: 1, Type: "agent_online", Title: "mine", Message: "my message", Severity: "info"}
	foreign := db.Notification{TenantID: 2, Type: "agent_online", Title: "theirs", Message: "other message", Severity: "info"}
	for _, row := range []*db.Notification{&own, &foreign} {
		if err := s.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	ownRoute := db.NotificationRoute{TenantID: 1, Name: "mine", Channel: "webhook", Target: "https://example.com/mine", MinSeverity: "info", Enabled: false}
	foreignRoute := db.NotificationRoute{TenantID: 2, Name: "theirs", Channel: "webhook", Target: "https://example.com/theirs", MinSeverity: "info", Enabled: false}
	for _, row := range []*db.NotificationRoute{&ownRoute, &foreignRoute} {
		if err := s.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}

	c, w := tenantScopedAdminContext(s, t, "notification-admin", 1)
	s.handleListNotifications(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "my message") || strings.Contains(w.Body.String(), "other message") {
		t.Fatalf("notification list leaked or lost rows: %d %s", w.Code, w.Body.String())
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	c.Params = gin.Params{{Key: "id", Value: itoa(int(foreign.ID))}}
	s.handleMarkNotificationRead(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign mark read = %d, want 404", w.Code)
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	c.Params = gin.Params{{Key: "id", Value: itoa(int(foreign.ID))}}
	s.handleDeleteNotification(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign delete = %d, want 404", w.Code)
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	s.handleMarkAllNotificationsRead(c)
	if w.Code != http.StatusOK {
		t.Fatalf("mark all = %d %s", w.Code, w.Body.String())
	}
	var ownRow, foreignRow db.Notification
	if err := s.db.First(&ownRow, own.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.First(&foreignRow, foreign.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !ownRow.Read || foreignRow.Read {
		t.Fatalf("read state crossed tenants: own=%v foreign=%v", ownRow.Read, foreignRow.Read)
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	s.handleClearAllNotifications(c)
	if w.Code != http.StatusOK {
		t.Fatalf("clear all = %d %s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.db.Model(&db.Notification{}).Where("id = ?", foreign.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("foreign notification changed: count=%d err=%v", count, err)
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	s.handleListNotificationRoutes(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"mine"`) || strings.Contains(w.Body.String(), `"name":"theirs"`) {
		t.Fatalf("route list leaked or lost rows: %d %s", w.Code, w.Body.String())
	}

	c, w = tenantScopedAdminContext(s, t, "notification-admin", 1)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/notification-routes/preview", strings.NewReader(`{"title":"mine","message":"x","severity":"info"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	s.handlePreviewNotification(c)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"name":"theirs"`) {
		t.Fatalf("route preview leaked foreign routes: %d %s", w.Code, w.Body.String())
	}
}

func TestDispatchNotificationStampsAgentTenant(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	agent := db.Implant{ID: "notification-agent", TenantID: 2, Hostname: "tenant-two", Status: "online"}
	if err := s.db.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	n := &db.Notification{Type: "agent_online", Title: "online", Message: "checked in", AgentID: agent.ID, Severity: "info"}
	s.DispatchNotification(n)
	if n.TenantID != 2 {
		t.Fatalf("notification tenant = %d, want 2", n.TenantID)
	}
	var stored db.Notification
	if err := s.db.First(&stored, n.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.TenantID != 2 {
		t.Fatalf("stored notification tenant = %d, want 2", stored.TenantID)
	}
}

func TestAlertEventRulesAreTenantScoped(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	for _, agent := range []db.Implant{
		{ID: "alert-mine", TenantID: 1, Hostname: "mine", Status: "online"},
		{ID: "alert-theirs", TenantID: 2, Hostname: "theirs", Status: "online"},
	} {
		if err := s.db.Create(&agent).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, rule := range []db.AlertRule{
		{TenantID: 1, Name: "mine", Type: "agent_online", Enabled: true},
		{TenantID: 2, Name: "theirs", Type: "agent_online", Enabled: true},
	} {
		if err := s.db.Create(&rule).Error; err != nil {
			t.Fatal(err)
		}
	}
	s.monitorCollector = NewMonitorCollector(s)
	s.TriggerAlertForEvent(Event{Type: EventImplantCheckin, AgentID: "alert-mine", TenantID: 1, AgentHost: "mine"})
	var alerts []db.Alert
	if err := s.db.Find(&alerts).Error; err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].TenantID != 1 || alerts[0].RuleID == 0 {
		t.Fatalf("alerts = %+v, want one tenant-1 alert", alerts)
	}
}
