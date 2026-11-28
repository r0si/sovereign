package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	forgecrypto "github.com/r0si/sovereign/internal/crypto"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/pkg/protocol"
)

func TestStoredArtifactsAreTenantScoped(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	forgecrypto.InitLootEncryption(testStorageKeyHex)

	const mine = "a4000000-0000-0000-0000-00000000aa01"
	const theirs = "a4000000-0000-0000-0000-00000000aa02"
	for _, agent := range []db.Implant{
		{ID: mine, TenantID: 1, Hostname: "mine", Status: "online"},
		{ID: theirs, TenantID: 2, Hostname: "theirs", Status: "online"},
	} {
		if err := s.db.Create(&agent).Error; err != nil {
			t.Fatal(err)
		}
	}
	var ownBH, foreignBH db.BloodHoundResult
	for _, row := range []*db.BloodHoundResult{
		{AgentID: mine, Summary: "my collection"},
		{AgentID: theirs, Summary: "other collection"},
	} {
		if err := s.db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
		if row.AgentID == mine {
			ownBH = *row
		} else {
			foreignBH = *row
		}
	}
	ownReport := db.GeneratedReport{TenantID: 1, Name: "my report", Content: "my content"}
	foreignReport := db.GeneratedReport{TenantID: 2, Name: "other report", Content: "other content"}
	for _, report := range []*db.GeneratedReport{&ownReport, &foreignReport} {
		if err := s.db.Create(report).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, hook := range []db.WebhookConfig{
		{TenantID: 1, Name: "mine", URL: "https://example.com/mine", EventType: "task.complete", Headers: `{"Authorization":"Bearer my-token"}`},
		{TenantID: 2, Name: "theirs", URL: "https://example.com/theirs", EventType: "task.complete", Headers: `{"Authorization":"Bearer other-token"}`},
	} {
		if err := s.db.Create(&hook).Error; err != nil {
			t.Fatal(err)
		}
	}

	c, w := tenantScopedAdminContext(s, t, "artifact-admin", 1)
	s.handleBloodHoundList(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "my collection") || strings.Contains(w.Body.String(), "other collection") {
		t.Fatalf("bloodhound list leaked or lost rows: %d %s", w.Code, w.Body.String())
	}

	c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
	s.handleBloodHoundStatus(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"total_collections":1`) {
		t.Fatalf("bloodhound status = %d %s", w.Code, w.Body.String())
	}

	c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
	c.Params = gin.Params{{Key: "id", Value: itoa(int(foreignBH.ID))}}
	s.handleBloodHoundDelete(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign bloodhound delete = %d, want 404", w.Code)
	}

	c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
	s.handleAPIGetReportHistory(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "my report") || strings.Contains(w.Body.String(), "other report") {
		t.Fatalf("report history leaked or lost rows: %d %s", w.Code, w.Body.String())
	}

	for _, tc := range []struct {
		path string
		call func(*gin.Context)
	}{
		{path: "/api/report/generated/" + itoa(int(foreignReport.ID)), call: s.handleAPIGetGeneratedReport},
		{path: "/api/report/generated/" + itoa(int(foreignReport.ID)) + "/download", call: s.handleAPIExportGeneratedReport},
		{path: "/api/report/" + itoa(int(foreignReport.ID)), call: s.handleAPIDeleteReport},
	} {
		c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
		c.Request = httptest.NewRequest(http.MethodGet, tc.path, nil)
		c.Params = gin.Params{{Key: "id", Value: itoa(int(foreignReport.ID))}}
		tc.call(c)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s = %d, want 404; body=%s", tc.path, w.Code, w.Body.String())
		}
	}

	c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
	s.handleAutomationPage(c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://example.com/mine") || strings.Contains(w.Body.String(), "https://example.com/theirs") || strings.Contains(w.Body.String(), "other-token") {
		t.Fatalf("automation page leaked or lost webhooks: %d %s", w.Code, w.Body.String())
	}

	var count int64
	if err := s.db.Model(&db.BloodHoundResult{}).Where("id = ?", foreignBH.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("foreign bloodhound row changed: count=%d err=%v", count, err)
	}
	if err := s.db.Model(&db.GeneratedReport{}).Where("id = ?", foreignReport.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("foreign report row changed: count=%d err=%v", count, err)
	}
	_ = ownBH
}

func bloodHoundMultipartRequest(t *testing.T, fields map[string]string, withFile bool) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if withFile {
		part, err := writer.CreateFormFile("file", "collection.zip")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte("zip")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/bloodhound/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestBloodHoundWritePathsRejectForeignAgentsAndTasks(t *testing.T) {
	ginSetTestMode(t)
	s := mustTenantServer(t)
	t.Chdir(t.TempDir())
	const mine = "a5000000-0000-0000-0000-00000000aa01"
	const theirs = "a5000000-0000-0000-0000-00000000aa02"
	for _, agent := range []db.Implant{
		{ID: mine, TenantID: 1, Hostname: "mine", Status: "online"},
		{ID: theirs, TenantID: 2, Hostname: "theirs", Status: "online"},
	} {
		if err := s.db.Create(&agent).Error; err != nil {
			t.Fatal(err)
		}
	}
	foreignTask := db.Task{AgentID: theirs, TenantID: 2, Type: protocol.TaskTypeSharpHound, Status: "running"}
	if err := s.db.Create(&foreignTask).Error; err != nil {
		t.Fatal(err)
	}

	c, w := tenantScopedAdminContext(s, t, "artifact-admin", 1)
	c.Request = bloodHoundMultipartRequest(t, map[string]string{"agent_id": theirs}, true)
	s.handleBloodHoundUpload(c)
	if w.Code != http.StatusNotFound {
		t.Fatalf("foreign upload = %d, want 404; body=%s", w.Code, w.Body.String())
	}

	c, w = tenantScopedAdminContext(s, t, "artifact-admin", 1)
	c.Request = bloodHoundMultipartRequest(t, map[string]string{"agent_id": mine, "task_id": itoa(int(foreignTask.ID))}, false)
	s.handleBloodHoundResult(c)
	if w.Code != http.StatusOK {
		t.Fatalf("owned result ingest = %d; body=%s", w.Code, w.Body.String())
	}
	var task db.Task
	if err := s.db.First(&task, foreignTask.ID).Error; err != nil {
		t.Fatal(err)
	}
	if task.Status != "running" {
		t.Fatalf("foreign task status = %q, want running", task.Status)
	}
}
