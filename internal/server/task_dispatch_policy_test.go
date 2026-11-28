package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/r0si/sovereign/internal/config"
	"github.com/r0si/sovereign/internal/db"
	"gorm.io/gorm"
)

func policyTestServer(t *testing.T) (*Server, db.Implant) {
	t.Helper()
	s := newTasksTestServer(t)
	s.cfg = &config.Config{}
	closed := time.Now().Add(-time.Hour)
	engagement := db.Engagement{
		ID: 1, TenantID: 0, Name: "closed", StartsAt: closed.Add(-time.Hour),
		EndsAt: closed, ClosedAt: &closed,
	}
	if err := s.db.Create(&engagement).Error; err != nil {
		t.Fatal(err)
	}
	agent := db.Implant{ID: "policy-agent", TenantID: 0, Hostname: "policy-host", EngagementID: &engagement.ID}
	if err := s.db.Create(&agent).Error; err != nil {
		t.Fatal(err)
	}
	return s, agent
}

func TestDirectTaskDispatchEnforcesClosedEngagement(t *testing.T) {
	s, agent := policyTestServer(t)
	if _, err := s.createTask(agent.ID, "shell", "whoami", "cmd", "", "", 0, 0); err == nil || !strings.Contains(err.Error(), "engagement") {
	}
	var count int64
	if err := s.db.Model(&db.Task{}).Where("agent_id = ?", agent.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rejected dispatch persisted %d tasks", count)
	}
}

func TestKillSwitchAllowsOnlyEmergencyDispatch(t *testing.T) {
	s, agent := policyTestServer(t)
	s.killSwitchMu.Lock()
	s.killSwitchArmed = true
	s.killSwitchToken = "policy-test-token"
	s.killSwitchMu.Unlock()
	t.Cleanup(func() {
		s.killSwitchMu.Lock()
		s.killSwitchArmed = false
		s.killSwitchToken = ""
		s.killSwitchMu.Unlock()
	})

	if _, err := s.createTask(agent.ID, "shell", "whoami", "cmd", "", "", 0, 0); err == nil || !strings.Contains(err.Error(), "kill-switch") {
		t.Fatalf("armed kill-switch error = %v", err)
	}
	abort, err := s.createTask(agent.ID, "abort", "42", "", "", "", 0, 0, withEmergencyAbortReservation())
	if err != nil {
		t.Fatalf("emergency abort rejected: %v", err)
	}
	if abort.Status != "running" || abort.ClaimedBy != agent.ID || abort.ClaimedAt.IsZero() {
		t.Fatalf("abort was not claimed immediately: %+v", abort)
	}
}

func TestBatchDispatchEnforcesClosedEngagement(t *testing.T) {
	s, agent := policyTestServer(t)
	if err := s.db.Model(&agent).Update("id", "batch-agent").Error; err != nil {
		t.Fatal(err)
	}
	w := batchCommandRequest(t, s, "shell", "whoami", "alice")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.db.Model(&db.Task{}).Where("agent_id = ?", "batch-agent").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("closed-engagement batch persisted %d tasks", count)
	}
}

func TestCampaignDispatchEnforcesClosedEngagement(t *testing.T) {
	s := newCampaignSeedTestServer(t)
	s.cfg = &config.Config{}
	seedCampaignWithAgents(t, s, "closed-campaign", "campaign-agent")
	closed := time.Now().Add(-time.Hour)
	engagement := db.Engagement{
		ID: 1, Name: "closed", StartsAt: closed.Add(-time.Hour), EndsAt: closed, ClosedAt: &closed,
	}
	if err := s.db.Create(&engagement).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&db.Implant{}).Where("id = ?", "campaign-agent").Update("engagement_id", engagement.ID).Error; err != nil {
		t.Fatal(err)
	}
	w := campaignSeedRequest(t, s, "closed-campaign", `{"template":"Standard Intrusion"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.db.Model(&db.Task{}).Where("agent_id = ?", "campaign-agent").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("closed-engagement campaign persisted %d tasks", count)
	}
}

func TestEngagementConvergenceCancelsAndInjectsAbortAtomically(t *testing.T) {
	s, agent := policyTestServer(t)
	pending := db.Task{AgentID: agent.ID, Type: "shell", Command: "whoami", Status: "pending"}
	approval := db.Task{AgentID: agent.ID, Type: "uninstall", Command: "self delete", Status: TaskStatusPendingApproval}
	running := db.Task{AgentID: agent.ID, Type: "shell", Command: "long-running", Status: "running"}
	if err := s.db.Create(&pending).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&approval).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&running).Error; err != nil {
		t.Fatal(err)
	}
	s.agentPendingTasks[agent.ID] = 3
	var convergence dispatchConvergence
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		var err error
		convergence, err = s.convergeAgentDispatch(tx, agent, time.Now(), "policy-test")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.applyDispatchConvergence(convergence)
	for _, id := range []uint{pending.ID, approval.ID} {
		var got db.Task
		if err := s.db.First(&got, id).Error; err != nil {
			t.Fatal(err)
		}
		if got.Status != "cancelled" || !strings.Contains(got.Error, "engagement") {
			t.Fatalf("task %d was not cancelled with engagement reason: %+v", id, got)
		}
	}
	var abort db.Task
	if err := s.db.Where("agent_id = ? AND type = ?", agent.ID, "abort").First(&abort).Error; err != nil {
		t.Fatal(err)
	}
	if abort.Status != "pending" || abort.Command != fmt.Sprintf("%d", running.ID) {
		t.Fatalf("convergence abort = %+v", abort)
	}
	var stillRunning db.Task
	if err := s.db.First(&stillRunning, running.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stillRunning.Status != "running" {
		t.Fatalf("running task was cancelled instead of aborted: %+v", stillRunning)
	}
	if got := s.agentPendingTasks[agent.ID]; got != 2 {
		t.Fatalf("pending counter = %d, want 2 for the running task and injected abort", got)
	}
}
