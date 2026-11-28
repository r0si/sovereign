package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/plugin"
	"github.com/r0si/sovereign/pkg/protocol"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// On failure writes JSON 404 and returns false.
func (s *Server) getAgentOrFail(c *gin.Context, id string) (db.Implant, bool) {
	var agent db.Implant
	q := s.db.Model(&db.Implant{})
	q = s.tenantScope(q, c)
	if err := q.First(&agent, "id = ?", id).Error; err != nil {
		slog.Error("Agent not found", "agent_id", id, "error", err)
		respondError(c, http.StatusNotFound, "agent not found")
		return agent, false
	}
	return agent, true
}

// TaskOption configures optional createTask behaviour.
type TaskOption func(*taskOptions)
type taskOptions struct {
	callerUserID   uint
	idempotencyKey string
	// forceWrite bypasses another operator's collaboration lock; non-empty
	// is the human-provided reason (audited). Only set for explicit admin
	// overrides — see issueAgentTask.
	forceWrite string
	// credentialID is a vault reference resolved by createTask. The parsed
	// secret never appears in the persisted public fields.
	credentialID     *uint
	credentialParams string
	// transferID ties a chunk task to a durable transfer session.
	transferID *uint
	direction  string
	final      bool
	// Edit baseline for optimistic concurrency.
	baseTaskID     *uint
	expectedSHA256 string
	// fileChainPrev/MAC carry a ready-made HMAC link for transfer chunks, so
	// the beacon cannot claim the task before the signature is persisted.
	fileChainPrev string
	fileChainMAC  string
	// resultEncryption is part of the REST request fingerprint even though
	// the key itself is minted after the row is created.
	resultEncryption bool
	taskKey          string
	systemStatus     string
	systemCreator    string
	reserveExtra     int
	priority         int
	claimNow         bool
}

// withSystemTaskMetadata preserves the system caller's approval intent and
// creator while all persistence/accounting stays in createTask.
func withSystemTaskMetadata(status, creator string) TaskOption {
	return func(o *taskOptions) {
		o.systemStatus = status
		o.systemCreator = creator
	}
}

// withEmergencyAbortReservation gives recall tasks urgent priority and the
// bounded reserved headroom used by the cancellation endpoint.
func withEmergencyAbortReservation() TaskOption {
	return func(o *taskOptions) {
		if o.reserveExtra < AbortReserveSlots {
			o.reserveExtra = AbortReserveSlots
		}
		o.priority = 3
		o.claimNow = true
	}
}

// WithCaller tags a createTask call with the operator user ID so the
// soft-lock check can exclude the caller from the conflict list.
func WithCaller(uid uint) TaskOption {
	return func(o *taskOptions) { o.callerUserID = uid }
}

// WithIdempotencyKey deduplicates task creation: when non-empty and a live
// (pending/pending_approval/running) task with the same key already exists
// on the agent, createTask returns it instead of inserting a duplicate
// (double-clicks, retried automation, replayed API calls).
func WithIdempotencyKey(key string) TaskOption {
	return func(o *taskOptions) { o.idempotencyKey = key }
}

// WithForceWrite overrides another operator's collaboration lock with a
// human reason (audited at creation). Callers must restrict this to explicit
// admin overrides; system paths never set it.
func WithForceWrite(reason string) TaskOption {
	return func(o *taskOptions) { o.forceWrite = reason }
}

// withResultEncryption records the requested result-sealing mode for
// idempotency comparison without minting or rotating a task key on replay.
func withResultEncryption(enabled bool) TaskOption {
	return func(o *taskOptions) { o.resultEncryption = enabled }
}

func withTaskKey(key string) TaskOption {
	return func(o *taskOptions) { o.taskKey = key }
}

var errIdempotencyConflict = errors.New("idempotency key belongs to a different task request")

func canonicalTaskFingerprint(agentID, taskType, command, shell, path, data string, offset, size int64, ref credentialTaskReference, opts taskOptions) string {
	if ref.ID != 0 {
		command, shell = ref.Command, ref.Shell
	}
	fields := []string{
		agentID, taskType, command, shell, path, data,
		strconv.FormatInt(offset, 10), strconv.FormatInt(size, 10),
		strconv.FormatBool(opts.resultEncryption),
	}
	if ref.ID != 0 {
		fields = append(fields, "credential", strconv.FormatUint(uint64(ref.ID), 10), ref.Fingerprint, ref.Params)
	}
	if opts.transferID != nil {
		fields = append(fields, "transfer", strconv.FormatUint(uint64(*opts.transferID), 10), opts.direction, strconv.FormatBool(opts.final))
	}
	if opts.baseTaskID != nil {
		fields = append(fields, "baseline", strconv.FormatUint(uint64(*opts.baseTaskID), 10), opts.expectedSHA256)
	}
	fields = append(fields, opts.fileChainPrev, opts.fileChainMAC)
	h := sha256.New()
	for _, field := range fields {
		fmt.Fprintf(h, "%d:", len(field))
		_, _ = h.Write([]byte(field))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func storedTaskFingerprint(task db.Task) string {
	ref := credentialTaskReference{}
	if task.CredentialID != nil {
		ref.ID = *task.CredentialID
		ref.Fingerprint = task.CredentialFingerprint
		ref.Params = task.CredentialParams
		ref.Command = task.ResolvedCommand
		ref.Shell = task.ResolvedShell
	}
	opts := taskOptions{
		resultEncryption: task.TaskKey != "",
		transferID:       task.TransferID,
		direction:        task.Direction,
		final:            task.Final,
		baseTaskID:       task.BaseTaskID,
		expectedSHA256:   task.ExpectedSHA256,
		fileChainPrev:    task.PrevMAC,
		fileChainMAC:     task.MAC,
	}
	return canonicalTaskFingerprint(task.AgentID, task.Type, task.Command, task.Shell, task.Path, task.Data, task.Offset, task.Size, ref, opts)
}

func replayIdempotentTask(existing db.Task, fingerprint string, ref credentialTaskReference) (*db.Task, error) {
	stored := existing.IdempotencyFingerprint
	if stored == "" {
		stored = storedTaskFingerprint(existing)
	}
	if stored != fingerprint {
		if ref.ID != 0 && (existing.CredentialID == nil || *existing.CredentialID != ref.ID || existing.CredentialFingerprint != ref.Fingerprint) {
			return nil, errCredentialReferenceConflict
		}
		return nil, errIdempotencyConflict
	}
	existing.IdempotentReplay = true
	return &existing, nil
}

// WithCredentialReference attaches a vault reference to a task. createTask
// resolves it before any policy/length check and stores the wire arguments in
// encrypted columns, keeping the public Command as "@cred:<id>".
func WithCredentialReference(id uint, params CredentialTaskParams) TaskOption {
	return func(o *taskOptions) {
		o.credentialID = &id
		o.credentialParams = encodeCredentialParams(params)
	}
}

// WithTransferRef binds a chunk task to a durable transfer session.
func WithTransferRef(transferID uint, direction string, final bool) TaskOption {
	return func(o *taskOptions) {
		o.transferID = &transferID
		o.direction = direction
		o.final = final
	}
}

// WithEditBaseline binds a write task to the read result it is based on.
func WithEditBaseline(baseTaskID uint, expectedSHA256 string) TaskOption {
	return func(o *taskOptions) {
		o.baseTaskID = &baseTaskID
		o.expectedSHA256 = expectedSHA256
	}
}

// WithFileChain supplies the signed HMAC link for a transfer/editor chunk.
// Both values are persisted in the INSERT, so an agent can never claim a
// half-signed task after a server restart or a slow second UPDATE.
func WithFileChain(prev, mac string) TaskOption {
	return func(o *taskOptions) {
		o.fileChainPrev = prev
		o.fileChainMAC = mac
	}
}

// callerOpts extracts the user_id from gin.Context and returns a WithCaller
// option. If the context has no user_id (e.g. automation, scripting), it
// returns nil so the soft-lock check is skipped.
func callerOpts(c *gin.Context) []TaskOption {
	if c == nil {
		return nil
	}
	uid, _ := c.Get("user_id")
	u, ok := uid.(uint)
	if !ok || u == 0 {
		return nil
	}
	return []TaskOption{WithCaller(u)}
}

// validateTaskCreation checks request validity and creation-only operator
// locks before calling the shared dispatch-time policy gate.
func (s *Server) validateTaskCreation(c *gin.Context, agentID, taskType, command, data, path string, callerUserID uint) error {
	return s.validateTaskCreationWithAgentShell(c, agentID, taskType, command, "", "", data, path, callerUserID, nil)
}

// validateTaskCreationWithAgent preserves the existing call shape for callers
// without a shell argument. Batch and single creation use the shell-aware form
// so required shell parameters cannot be bypassed or falsely rejected.
func (s *Server) validateTaskCreationWithAgent(c *gin.Context, agentID, taskType, command, data, path string, callerUserID uint, preloadedAgent *db.Implant) error {
	return s.validateTaskCreationWithAgentShell(c, agentID, taskType, command, "", "", data, path, callerUserID, preloadedAgent)
}

func (s *Server) validateTaskCreationWithAgentShell(c *gin.Context, agentID, taskType, command, shell, expectedSHA256, data, path string, callerUserID uint, preloadedAgent *db.Implant) error {
	agent, err := s.agentForDispatch(agentID, preloadedAgent)
	if err != nil {
		return err
	}
	if err := validateTaskArguments(taskType, command, shell, path, data, expectedSHA256); err != nil {
		return err
	}
	if err := s.authorizeTaskDispatch(*agent, taskType, command, data, path); err != nil {
		return err
	}

	// Creation-only soft-lock: approval and claim must not inherit a stale
	// operator browsing session from the time the task was originally created.
	if callerUserID != 0 && s.operatorSessions != nil {
		if others := s.operatorSessions.ActiveOperatorsForAgent(agentID, callerUserID); len(others) > 0 {
			return fmt.Errorf("agent conflict: %s is being actively operated by %s", agentID, joinUsernames(others))
		}
	}
	return nil
}

// validateTaskArguments is shared by operator, system and batched creation.
// It validates the complete request without applying dispatch-time policy.
func validateTaskArguments(taskType, command, shell, path, data, expectedSHA256 string) error {
	if !IsKnownTaskType(taskType) && !protocol.ValidTaskType(taskType) {
		return taskRequestErrorf("unknown task type: %s", taskType)
	}
	if len(command) > MaxCommandLength {
		return taskRequestErrorf("command too long (max %d characters)", MaxCommandLength)
	}
	info, ok := getTaskTypeInfo(taskType)
	if !ok {
		return nil
	}
	for _, p := range info.Parameters {
		if !p.Required {
			continue
		}
		value := command
		switch p.Name {
		case "shell":
			value = shell
		case "path":
			value = path
		case "expected_sha256":
			value = expectedSHA256
		case "data":
			value = data
		case "command":
		default:
			continue
		}
		if value == "" {
			return taskRequestErrorf("task type %s requires '%s' parameter", taskType, p.Name)
		}
	}
	return nil
}

// emergencyDispatchTask is the complete emergency allowlist. These tasks may
// bypass the armed kill-switch and engagement/implant deadline so recall and
// self-destruction remain deliverable; RoE, OPSEC and argument checks still run.
func emergencyDispatchTask(taskType string) bool {
	return taskType == protocol.TaskTypeAbort || taskType == protocol.TaskTypeKill || taskType == protocol.TaskTypeUninstall
}

// authorizeTaskDispatch is the pure dispatch policy gate used by creation,
// approval and both beacon claim paths. The implant must already be loaded;
// all lookup failures are returned to the caller rather than treated as an
// unconstrained implant.
func (s *Server) authorizeTaskDispatch(agent db.Implant, taskType, command, data, path string) error {
	return s.authorizeTaskDispatchOn(agent, taskType, command, data, path, s.db, true)
}

func agentSupportsTaskType(agent db.Implant, taskType string) bool {
	if strings.TrimSpace(agent.TaskTypes) == "" {
		return true // legacy agents predate capability advertising
	}
	canonical, _ := protocol.ResolveAlias(taskType)
	for _, supported := range strings.Split(agent.TaskTypes, ",") {
		supported = strings.TrimSpace(supported)
		if supported == taskType || supported == canonical {
			return true
		}
	}
	return false
}

func (s *Server) authorizeTaskDispatchOn(agent db.Implant, taskType, command, data, path string, database *gorm.DB, audit bool) error {
	if agent.ID == "" {
		return fmt.Errorf("agent lookup failed: implant not found")
	}
	if err := s.checkRoELoaded(agent, taskType, command, data, path); err != nil {
		return err
	}
	if taskType == protocol.TaskTypeLPortFwdStart && !s.lportFwdAllowed() {
		return fmt.Errorf("lportfwd is disabled by server configuration (server.lportfwd_enabled)")
	}
	if s.opsecAdaptive != nil && s.opsecAdaptive.ShouldBlockAction(agent.ID, taskType) {
		if audit {
			s.LogAuditRecord(nil, "opsec_block", "agent", agent.ID,
				"blocked "+taskType+" (critical threat level)", false, nil)
		}
		return fmt.Errorf("blocked by adaptive opsec: %s is not allowed on a critical-threat host", taskType)
	}
	emergency := emergencyDispatchTask(taskType)
	if !emergency && !agentSupportsTaskType(agent, taskType) {
		return fmt.Errorf("agent does not support task type %s", taskType)
	}
	armed, _ := s.killSwitchState()
	if armed && !emergency {
		return fmt.Errorf("fleet kill-switch is armed; only abort, kill and uninstall tasks may be dispatched")
	}
	if emergency {
		return nil
	}
	engagement, err := s.dispatchEngagementOn(agent, database)
	if err != nil {
		return err
	}
	now := time.Now()
	if s.engagementNotStarted(agent, engagement, now) {
		if audit {
			s.LogAuditRecord(nil, "agent_not_started_block", "agent", agent.ID,
				fmt.Sprintf("refused %s: engagement starts %s", taskType, engagement.StartsAt.UTC().Format(time.RFC3339)), false, nil)
		}
		return fmt.Errorf("agent not in scope yet: the engagement for this implant starts at %s",
			engagement.StartsAt.UTC().Format(time.RFC3339))
	}
	if deadline := effectiveDeadlineFor(agent, engagement); deadline != nil && now.After(*deadline) {
		when := deadline.UTC().Format(time.RFC3339)
		if audit {
			s.LogAuditRecord(nil, "agent_expired_block", "agent", agent.ID,
				fmt.Sprintf("refused %s: deadline passed (%s)", taskType, when), false, nil)
		}
		return fmt.Errorf("agent expired: the engagement deadline for this implant passed at %s", when)
	}
	return nil
}

// taskDispatchFields returns the real wire arguments for policy evaluation,
// including credential-resolved commands which are hidden from task.Command.
func taskDispatchFields(t db.Task) (command, shell, path, data string, err error) {
	command, shell, err = taskWireArgs(t)
	if err != nil {
		return "", "", "", "", err
	}
	return command, shell, t.Path, t.Data, nil
}

// authorizeStoredTaskDispatch re-evaluates the policy in force now against
// the task's real wire arguments. It deliberately does not run creation-only
// soft-lock/AgentLock checks.
func (s *Server) authorizeStoredTaskDispatch(task db.Task) error {
	agent, err := s.agentForDispatch(task.AgentID, nil)
	if err != nil {
		return err
	}
	command, _, path, data, err := taskDispatchFields(task)
	if err != nil {
		return err
	}
	return s.authorizeTaskDispatch(*agent, task.Type, command, data, path)
}

// dispatchConvergence records post-commit effects for tasks stopped because
// their engagement closed or expired. Counters and hooks are applied only
// after the transaction commits.
type dispatchConvergence struct {
	cancelled []db.Task
	aborts    []db.Task
}

func dispatchAgentExpiredOn(database *gorm.DB, agent db.Implant, now time.Time) (bool, error) {
	engagement, err := (&Server{}).dispatchEngagementOn(agent, database)
	if err != nil {
		return false, err
	}
	deadline := effectiveDeadlineFor(agent, engagement)
	return deadline != nil && !deadline.IsZero() && !now.Before(*deadline), nil
}

// convergeAgentDispatch cancels queued work and injects one urgent abort for
// each running task when an agent's effective deadline has passed. It runs in
// the caller's transaction so close/claim and convergence cannot interleave.
func (s *Server) convergeAgentDispatch(tx *gorm.DB, agent db.Implant, now time.Time, creator string) (dispatchConvergence, error) {
	var out dispatchConvergence
	expired, err := dispatchAgentExpiredOn(tx, agent, now)
	if err != nil || !expired {
		return out, err
	}
	// Abort is emergency policy: it remains deliverable in a closed/expired
	// engagement. Authorize before any task row is changed or inserted.
	if err := s.authorizeTaskDispatchOn(agent, protocol.TaskTypeAbort, "0", "", "", tx, false); err != nil {
		return out, err
	}
	var live []db.Task
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id, tenant_id, agent_id, type, command, status, error").
		Where("agent_id = ? AND status IN ?", agent.ID, []string{"pending", TaskStatusPendingApproval, "running"}).
		Find(&live).Error; err != nil {
		return out, err
	}
	var pendingIDs []uint
	for _, task := range live {
		if task.Status == "running" {
			continue
		}
		pendingIDs = append(pendingIDs, task.ID)
	}
	if len(pendingIDs) > 0 {
		res := tx.Model(&db.Task{}).Where("id IN ? AND status IN ?", pendingIDs,
			[]string{"pending", TaskStatusPendingApproval}).
			Updates(map[string]interface{}{"status": "cancelled", "error": "engagement closed or expired"})
		if res.Error != nil {
			return out, res.Error
		}
		for _, task := range live {
			if task.Status == "running" {
				continue
			}
			task.Status = "cancelled"
			task.Error = "engagement closed or expired"
			out.cancelled = append(out.cancelled, task)
		}
	}
	for _, task := range live {
		if task.Status != "running" {
			continue
		}
		command := strconv.FormatUint(uint64(task.ID), 10)
		var existing int64
		if err := tx.Model(&db.Task{}).
			Where("agent_id = ? AND type = ? AND command = ? AND status IN ?", agent.ID,
				protocol.TaskTypeAbort, command, []string{"pending", "running"}).Count(&existing).Error; err != nil {
			return out, err
		}
		if existing > 0 {
			continue
		}
		out.aborts = append(out.aborts, db.Task{
			TenantID: task.TenantID, AgentID: agent.ID, Type: protocol.TaskTypeAbort,
			Command: command, Status: "pending", Priority: 3, CreatedBy: creator,
		})
	}
	if len(out.aborts) > 0 {
		// A closing engagement may have many running tasks. Reserve exactly
		// the emergency headroom needed rather than the normal two slots.
		if err := s.trackPendingTaskReserved(agent.ID, len(out.aborts)); err != nil {
			out.aborts = nil
			return out, err
		}
		if err := tx.Create(&out.aborts).Error; err != nil {
			for range out.aborts {
				s.decPendingTasks(agent.ID)
			}
			out.aborts = nil
			return out, err
		}
	}
	return out, nil
}

func (s *Server) applyDispatchConvergence(result dispatchConvergence) {
	for _, task := range result.cancelled {
		s.decPendingTasks(task.AgentID)
		s.broadcastTaskUpdate(task.AgentID, task)
	}
	for i := range result.aborts {
		task := &result.aborts[i]
		s.fireTaskCreatedHook(task.AgentID, task.ID, task.Type, task.Command)
		if s.metrics != nil {
			s.metrics.TasksTotal.Inc()
		}
		s.broadcastTaskUpdate(task.AgentID, *task)
	}
}

func (s *Server) releaseDispatchConvergence(result dispatchConvergence) {
	for _, task := range result.aborts {
		s.decPendingTasks(task.AgentID)
	}
}

// isUniqueViolation reports whether err is a unique-constraint violation on
// either supported driver (sqlite: "UNIQUE constraint failed", postgres:
// "duplicate key value violates unique constraint" / SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "duplicate key value") ||
		strings.Contains(msg, "23505")
}

// taskRequestError marks a createTask failure that was caused by the request
// itself (unknown type, missing parameter, RoE/OPSEC refusal, queue or lock
// limits) instead of a server fault. API handlers answer 400 with the message
// so operators see why nothing was queued; internal/DB failures keep the
// generic 500.
type taskRequestError struct{ msg string }

func (e *taskRequestError) Error() string { return e.msg }

func taskRequestErrorf(format string, args ...any) error {
	return &taskRequestError{msg: fmt.Sprintf(format, args...)}
}

// createTask creates and persists a new pending task. Returns the task or error.
func (s *Server) createTask(agentID, taskType, command, shell, path, data string, offset, size int64, opts ...TaskOption) (*db.Task, error) {
	var tOpts taskOptions
	for _, opt := range opts {
		opt(&tOpts)
	}
	var ref credentialTaskReference
	if tOpts.credentialID != nil && *tOpts.credentialID != 0 {
		if !credentialReferenceTaskTypes(taskType) {
			return nil, taskRequestErrorf("credential references are not supported for task type %s", taskType)
		}
		if command != "" || shell != "" || path != "" || data != "" {
			return nil, taskRequestErrorf("credential reference tasks must not carry inline secret parameters")
		}
		resolved, rc, rp, rd, fingerprint, label, err := s.prepareCredentialTask(
			agentID, taskType, credentialTaskReference{ID: *tOpts.credentialID, Params: tOpts.credentialParams})
		if err != nil {
			return nil, &taskRequestError{msg: sanitizeError(err, "invalid credential reference")}
		}
		ref = credentialTaskReference{
			ID: *tOpts.credentialID, Params: tOpts.credentialParams,
			Command: resolved, Shell: rc, Path: rp, Data: rd,
			Fingerprint: fingerprint, Label: label,
		}
		// RoE/OPSEC, length and required-parameter checks must see the REAL
		// arguments: a safe placeholder would let a long or forbidden command
		// through policy and fail only on the wire.
		command, shell, path = resolved, rc, rp
		if taskType == "password_spray" {
			data = rd
		}
	}
	// Clamp before validation so policy and the persisted request see the
	// same bounded command.
	if taskType == protocol.TaskTypeSetSleep {
		var err error
		command, err = clampSetSleepCommand(command)
		if err != nil {
			return nil, &taskRequestError{msg: err.Error()}
		}
	}
	if err := s.validateTaskCreationWithAgentShell(nil, agentID, taskType, command, shell, tOpts.expectedSHA256, data, path, tOpts.callerUserID, nil); err != nil {
		return nil, &taskRequestError{msg: err.Error()}
	}

	// Collaboration lock: another operator's live lock blocks creation unless
	// this call carries an explicit admin force override (audited inside).
	if err := s.checkAgentLockForCreate(agentID, &tOpts); err != nil {
		return nil, &taskRequestError{msg: err.Error()}
	}

	// Idempotency: a live task with the same key short-circuits creation.
	// Checked before the pending-counter increment so dedup hits never
	// consume quota. Terminal tasks (completed/failed/cancelled/timeout)
	// never block key reuse.
	var idempotencyFingerprint string
	if key := strings.TrimSpace(tOpts.idempotencyKey); key != "" {
		if len(key) > 64 {
			return nil, taskRequestErrorf("idempotency key too long (max 64 characters)")
		}
		idempotencyFingerprint = canonicalTaskFingerprint(agentID, taskType, command, shell, path, data, offset, size, ref, tOpts)
		var existing db.Task
		if err := s.db.Where("agent_id = ? AND idempotency_key = ? AND status IN ?",
			agentID, key, []string{"pending", TaskStatusPendingApproval, "running"}).
			Order("id DESC").First(&existing).Error; err == nil {
			return replayIdempotentTask(existing, idempotencyFingerprint, ref)
		}
		tOpts.idempotencyKey = key
	}

	s.agentPendingTasksMu.Lock()
	pending := s.agentPendingTasks[agentID]
	limit := MaxPendingTasksPerAgent + tOpts.reserveExtra
	if pending >= limit {
		s.agentPendingTasksMu.Unlock()
		return nil, taskRequestErrorf("agent %s has %d pending tasks (limit %d)", agentID, pending, limit)
	}
	s.agentPendingTasks[agentID] = pending + 1
	s.agentPendingTasksMu.Unlock()
	priority := tOpts.priority
	if priority == 0 {
		priority = 1
	}

	task := db.Task{
		AgentID:        agentID,
		Type:           taskType,
		Command:        command,
		Shell:          shell,
		Path:           path,
		Data:           data,
		Offset:         offset,
		Size:           size,
		Status:         "pending",
		Priority:       priority,
		TransferID:     tOpts.transferID,
		Direction:      tOpts.direction,
		Final:          tOpts.final,
		BaseTaskID:     tOpts.baseTaskID,
		ExpectedSHA256: tOpts.expectedSHA256,
		TaskKey:        tOpts.taskKey,
		PrevMAC:        tOpts.fileChainPrev,
		MAC:            tOpts.fileChainMAC,
		CreatedBy:      tOpts.systemCreator,
	}
	if tOpts.claimNow {
		now := time.Now()
		task.ClaimedBy = agentID
		task.ClaimedAt = now
	}
	if ref.ID != 0 {
		id := ref.ID
		task.Command = fmt.Sprintf("@cred:%d", id)
		task.Shell = ""
		task.CredentialID = &id
		task.CredentialFingerprint = ref.Fingerprint
		task.CredentialLabel = ref.Label
		task.CredentialParams = ref.Params
		task.ResolvedCommand = ref.Command
		task.ResolvedShell = ref.Shell
	}
	// Inherit the agent's tenant so tenant-scoped single-task reads
	// (handleGetTaskStatus/apiGetTask) see the row. Previously tasks were
	// always tenant 0 while operators sit on tenant 1, so list (agent-gated,
	// no task-tenant filter) showed tasks that single-fetch 404d.
	ag, err := s.agentForDispatch(agentID, nil)
	if err != nil {
		s.decPendingTasks(agentID)
		return nil, err
	}
	task.TenantID = ag.TenantID
	if tOpts.idempotencyKey != "" {
		task.IdempotencyKey = tOpts.idempotencyKey
		task.IdempotencyFingerprint = idempotencyFingerprint
	}

	task.Status = s.resolveInitialTaskStatusFor(taskType, tOpts.credentialID)
	if tOpts.systemStatus == TaskStatusPendingApproval {
		task.Status = TaskStatusPendingApproval
	}
	if tOpts.claimNow {
		task.Status = "running"
	}
	if task.Status == TaskStatusPendingApproval {
		exp := time.Now().Add(ApprovalExpiryDuration)
		task.ApprovalExpiresAt = &exp
	}
	if err := s.db.Create(&task).Error; err != nil {
		s.decPendingTasks(agentID)
		// Close the SELECT-then-INSERT race at the database: a concurrent
		// creation with the same key hits the partial unique index. Return
		// the winner instead of an error so double-clicks/retries collapse.
		if tOpts.idempotencyKey != "" && isUniqueViolation(err) {
			var existing db.Task
			if e2 := s.db.Where("agent_id = ? AND idempotency_key = ? AND status IN ?",
				agentID, tOpts.idempotencyKey, []string{"pending", TaskStatusPendingApproval, "running"}).
				Order("id DESC").First(&existing).Error; e2 == nil {
				return replayIdempotentTask(existing, idempotencyFingerprint, ref)
			}
		}
		return nil, err
	}
	if task.Status == TaskStatusPendingApproval {
		// Upserted on (task_id, kind); a replayed create cannot duplicate the card.
		s.postTaskApprovalChat(task, "approval",
			fmt.Sprintf("Task #%d (%s) on %s by %s awaits approval", task.ID, task.Type, task.AgentID, task.CreatedBy),
			fmt.Sprintf(`{"task_id":%d,"type":%q,"status":"pending_approval"}`, task.ID, task.Type))
	}
	// lportfwd bookkeeping: register the operator-declared target so
	// connect frames can be validated against it, and clear declarations on
	// stop (P1 — closes the arbitrary-dial SSRF via agent-controlled frames).
	switch taskType {
	case protocol.TaskTypeLPortFwdStart:
		if _, target, ok := parseLPortFwdCommand(command); ok {
			s.registerLPortFwdDecl(agentID, target)
		}
	case protocol.TaskTypeLPortFwdStop:
		s.clearLPortFwdDecl(agentID)
	}
	if s.pluginManager != nil {
		s.fireTaskCreatedHook(agentID, task.ID, taskType, command)
	}
	if s.metrics != nil {
		s.metrics.TasksTotal.Inc()
	}
	return &task, nil
}

// createSystemTask delegates to createTask so automation, AI, retry and
// configuration tasks cannot bypass type/parameter, command bounds, policy,
// approval, tenant, capacity, hook or metric semantics. Only creator and an
// explicit pending_approval intent differ from operator creation.
func (s *Server) createSystemTask(agentID, taskType, command, shell, status, createdBy string) (*db.Task, error) {
	return s.createSystemTaskWithData(agentID, taskType, command, shell, "", status, createdBy)
}

func (s *Server) createSystemTaskWithData(agentID, taskType, command, shell, data, status, createdBy string) (*db.Task, error) {
	if agentID == "" {
		return nil, taskRequestErrorf("agent id required")
	}
	if taskType == "" {
		return nil, taskRequestErrorf("task type required")
	}
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != TaskStatusPendingApproval {
		return nil, taskRequestErrorf("invalid system task status %q", status)
	}
	return s.createTask(agentID, taskType, command, shell, "", data, 0, 0,
		withSystemTaskMetadata(status, createdBy))
}

// fireTaskCreatedHook runs the task_created plugin hook best-effort in the
// background. Shared by createTask and createSystemTask so direct inserts
// can't silently skip subscriber automation.
func (s *Server) fireTaskCreatedHook(agentID string, taskID uint, taskType, command string) {
	if s.pluginManager == nil {
		return
	}
	// Route through the bounded worker pool, not a raw goroutine: a bulk
	// dispatch of N agents used to spawn N unbounded goroutines, each running
	// plugin hooks that can block on SQLITE_BUSY, stalling shutdown in wg.Wait.
	s.runTaskWorker("task_created", func() {
		if err := s.pluginManager.ExecuteHook(s.ctx, plugin.Event{
			Type:      plugin.EventTaskCreated,
			Timestamp: time.Now(),
			AgentID:   agentID,
			Payload: map[string]interface{}{
				"task_id":   taskID,
				"task_type": taskType,
				"command":   command,
			},
		}); err != nil {
			slog.Warn("Hook errors on task_created event", "agent_id", agentID, "task_id", taskID, "err", err)
		}
	})
}

// clampSetSleepCommand bounds a set_sleep "interval,jitter" command to the
// agent-safe range (interval 1..86400s, jitter 0..100%). Malformed input
// passes through untouched so downstream validation still reports the
// original error (same contract as clampSleepString).
func clampSetSleepCommand(command string) (string, error) {
	parts := strings.Split(command, ",")
	if len(parts) != 2 {
		return command, nil
	}
	interval, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	jitter, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return command, nil
	}
	if interval < 1 {
		interval = 1
	}
	if interval > 86400 {
		interval = 86400
	}
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 100 {
		jitter = 100
	}
	return fmt.Sprintf("%d,%d", interval, jitter), nil
}

// resolveInitialTaskStatus returns the status a newly created task should start
// in. When operator approval is required and the task type is flagged, the task
// waits in pending_approval; otherwise it is immediately pending. Centralizing
// this keeps the single-task and bulk/batch paths consistent so the two-man
// rule cannot be bypassed through the batch endpoint.
func (s *Server) resolveInitialTaskStatus(taskType string) string {
	s.configMu.RLock()
	requireApproval := s.cfg != nil && s.cfg.Security.RequireApproval
	s.configMu.RUnlock()
	if requireApproval {
		if info, ok := getTaskTypeInfo(taskType); ok && info.RequiresApproval {
			return TaskStatusPendingApproval
		}
	}
	return "pending"
}

// resolveInitialTaskStatusFor adds the vault-reference approval rule: a
// referenced cred_check/token_make waits for a second operator whenever
// approval is enabled, even when the inline task type itself is not flagged.
// dangerousTaskTypes is deliberately unchanged.
func (s *Server) resolveInitialTaskStatusFor(taskType string, credentialID *uint) string {
	status := s.resolveInitialTaskStatus(taskType)
	if status != "pending" || credentialID == nil || *credentialID == 0 {
		return status
	}
	if taskType == "cred_check" || taskType == "token_make" {
		return TaskStatusPendingApproval
	}
	return status
}

// TaskSpec describes a single agent task issued from an HTTP handler.
type TaskSpec struct {
	Type             string
	Command          string
	Shell            string
	Path             string
	Data             string
	Offset           int64
	Size             int64
	IdempotencyKey   string
	CredentialID     *uint
	CredentialParams CredentialTaskParams
	TransferID       *uint
	Direction        string
	Final            bool
	BaseTaskID       *uint
	ExpectedSHA256   string
	FileChainPrev    string
	FileChainMAC     string
}

// issueAgentTask is the single choke point for handler-issued tasks: it runs
// the tenant-scoped agent lookup, creates the task with the caller's operator
// identity (so the soft-lock gate applies), and maps creation failures to the
// correct client status via respondTaskError. On failure it writes the error
// response and returns nil; on success it returns the task WITHOUT writing a
// response, leaving the caller to dispatch (dispatchTask) or render custom JSON.
func (s *Server) issueAgentTask(c *gin.Context, id string, spec TaskSpec) *db.Task {
	if _, ok := s.getAgentOrFail(c, id); !ok {
		return nil
	}
	opts := append(callerOpts(c), WithIdempotencyKey(spec.IdempotencyKey))
	if spec.CredentialID != nil && *spec.CredentialID != 0 {
		if !requireCredentialReferencePermission(c, spec.CredentialID) {
			respondError(c, http.StatusForbidden, "credentials.read is required to reference vault entries")
			return nil
		}
		opts = append(opts, WithCredentialReference(*spec.CredentialID, spec.CredentialParams))
	}
	if spec.TransferID != nil {
		opts = append(opts, WithTransferRef(*spec.TransferID, spec.Direction, spec.Final))
	}
	if spec.BaseTaskID != nil {
		opts = append(opts, WithEditBaseline(*spec.BaseTaskID, spec.ExpectedSHA256))
	}
	if spec.FileChainMAC != "" {
		opts = append(opts, WithFileChain(spec.FileChainPrev, spec.FileChainMAC))
	}
	// Admin force override for another operator's collaboration lock. The
	// reason is mandatory and audited inside createTask's lock gate.
	if c.Query("force") == "true" && s.isAdmin(c) {
		reason := strings.TrimSpace(c.Query("reason"))
		if reason == "" {
			reason = "no reason given"
		}
		opts = append(opts, WithForceWrite(reason))
	}
	task, err := s.createTask(id, spec.Type, spec.Command, spec.Shell, spec.Path, spec.Data, spec.Offset, spec.Size, opts...)
	if err != nil {
		respondTaskError(c, err)
		return nil
	}
	return task
}

// checkAgentLockForCreate enforces another operator's live collaboration lock
// on every createTask path (handlers, bulk, macros, scheduler): non-holders
// get a 409 naming the holder, unless an explicit admin force override
// (WithForceWrite) carries an audited reason. System/automation callers
// (callerUserID == 0) bypass UI-level locks by design and are documented as
// doing so; direct AI row inserts bypass all creation gates (pre-existing).
func (s *Server) checkAgentLockForCreate(agentID string, tOpts *taskOptions) error {
	var lock db.AgentLock
	if err := s.db.Where("agent_id = ?", agentID).First(&lock).Error; err != nil {
		return nil // no lock row: free to write
	}
	holder, live := lockHolderOf(&lock, time.Now())
	if !live || holder == "" {
		return nil
	}
	if tOpts.callerUserID != 0 {
		var me string
		if err := s.db.Model(&db.User{}).Where("id = ?", tOpts.callerUserID).Pluck("username", &me).Error; err == nil && me == holder {
			return nil
		}
	} else {
		return nil // system/automation path: not subject to UI locks
	}
	if tOpts.forceWrite != "" {
		s.LogAuditRecord(nil, "collab_lock_force_write", "agent", agentID,
			"task created on agent locked by "+holder+": "+tOpts.forceWrite, true, nil)
		return nil
	}
	return fmt.Errorf("agent conflict: agent is locked by %s", holder)
}

// taskArgsHash is a short non-reversible fingerprint of a task's arguments
// for audit trails. Raw commands may carry credentials, so only the hash is
// logged — enough to correlate create/approve/execute records of one task.
func taskArgsHash(t *db.Task) string {
	command, shell, err := taskWireArgs(*t)
	if err != nil {
		// Never fall back to the safe placeholder: an audit fingerprint that
		// omits the real arguments cannot correlate approval with execution.
		command, shell = t.Command, t.Shell
	}
	sum := sha256.Sum256([]byte(t.Type + "\x00" + command + "\x00" + shell + "\x00" + t.Path + "\x00" + t.Data))
	return hex.EncodeToString(sum[:])[:16]
}

// persistTaskCreator stamps the creator onto the stored task.
//
// The in-memory value already feeds the audit record, so an ignored write failure left the database
// disagreeing with the audit trail about who ordered a task - the one field an investigation needs.
func (s *Server) persistTaskCreator(task *db.Task, username string) {
	if task == nil || username == "" {
		return
	}
	task.CreatedBy = username
	if err := s.db.Model(task).Update("created_by", username).Error; err != nil {
		slog.Error("Failed to persist task creator", "task_id", task.ID, "creator", username, "error", err)
	}
}

// auditTaskCreation is the shared creation audit for REST and operator dispatch.
// It records correlation identifiers only: raw commands, file contents, resolved
// credentials and results must never enter the long-lived audit chain.
func (s *Server) auditTaskCreation(c *gin.Context, task *db.Task) {
	if task == nil || task.IdempotentReplay {
		return
	}
	if c != nil {
		if username := s.currentUsername(c); username != "" && task.CreatedBy == "" {
			s.persistTaskCreator(task, username)
		}
	}
	s.LogAuditRecord(c, "task_create", "task", task.AgentID,
		fmt.Sprintf("task_id=%d agent_id=%s created_by=%s args=%s",
			task.ID, task.AgentID, task.CreatedBy, taskArgsHash(task)), true, nil)
}

// dispatchTask audits creation, broadcasts the update via WS, and returns success JSON.
func (s *Server) dispatchTask(c *gin.Context, task *db.Task, _, _ string) {
	s.auditTaskCreation(c, task)
	s.broadcastTaskUpdate(task.AgentID, *task)
	respond(c, gin.H{"task_id": task.ID})
}

// flippedSet re-reads which of ids now carry status. It lets sweep passes
// restrict side effects (broadcasts, counter decs) to rows their guarded
// UPDATE actually flipped, instead of the stale SELECT list — a result
// landing between the statements is skipped by the UPDATE guard yet would
// otherwise still be broadcast as failed and double-dec the agent counter.
// ok=false means the re-read itself failed; callers then fall back to the
// full list (today's behavior) rather than dropping side effects.
func (s *Server) flippedSet(ids []uint, status string) (map[uint]bool, bool) {
	out := make(map[uint]bool, len(ids))
	if len(ids) == 0 {
		return out, true
	}
	var rows []struct {
		ID uint
	}
	if err := s.db.Model(&db.Task{}).Select("id").Where("id IN ? AND status = ?", ids, status).Find(&rows).Error; err != nil {
		slog.Warn("Sweep calibration re-read failed, keeping full side-effect set", "error", err)
		for _, id := range ids {
			out[id] = true
		}
		return out, false
	}
	for _, r := range rows {
		out[r.ID] = true
	}
	return out, true
}

// maxSweepPasses bounds the per-sweep paging loop below: a fleet with more
// than one LIMIT page of stale tasks drains progressively instead of
// starving everything past the first 1000 rows every 5 minutes.
const maxSweepPasses = 5

// requeueStaleTasks retries only tasks whose delivery was never acknowledged,
// capped at 3 delivery attempts; exhausted tasks are failed instead of
// being requeued forever.
//
// The static StaleRunningTaskTimeout is a floor: agents with long sleep
// intervals get max(static, 3x their interval) so a healthy long-sleep
// agent's in-flight task is neither requeued nor failed prematurely.
func (s *Server) requeueStaleTasks() {
	for pass := 0; pass < maxSweepPasses; pass++ {
		if !s.requeueStaleTasksPass() {
			return
		}
	}
}

// requeueStaleTasksPass runs one LIMIT page; it reports whether a full page
// was seen (caller pages again to avoid starving large fleets).
func (s *Server) requeueStaleTasksPass() bool {
	cutoff := time.Now().Add(-StaleRunningTaskTimeout)
	fullPage := false

	// Legacy "sent" rows: nothing creates or claims sent anymore (fetch only
	// moves pending→running), so any row still sitting in sent is a zombie.
	// Fail it outright — never requeue, or ancient rows would resurrect and
	// redeliver stale commands to live agents.
	var sentTasks []db.Task
	if err := s.db.Where("status = ? AND created_at < ? AND claimed_at < ?", "sent", cutoff, cutoff).Limit(1000).Find(&sentTasks).Error; err != nil {
		slog.Error("Failed to find legacy sent tasks", "error", err)
		return false
	}
	fullPage = len(sentTasks) == 1000
	if len(sentTasks) > 0 {
		sentIDs := make([]uint, len(sentTasks))
		for i, t := range sentTasks {
			sentIDs[i] = t.ID
		}
		res := s.withBusyRetryDB("sweep", func() *gorm.DB {
			return s.db.Model(&db.Task{}).Where("id IN ? AND status = ?", sentIDs, "sent").
				Updates(map[string]interface{}{
					"status": "failed",
					"error":  "legacy sent status retired (never dispatched)",
				})
		})
		if res.Error != nil {
			slog.Error("Failed to retire legacy sent tasks", "count", len(sentIDs), "error", res.Error)
			return false
		}
		// Calibrate side effects to rows actually flipped: a concurrent
		// transition narrows RowsAffected, and the skipped rows must get
		// neither broadcast nor dec. Full batches skip the re-read.
		flipped := make(map[uint]bool, len(sentIDs))
		for _, id := range sentIDs {
			flipped[id] = true
		}
		if res.RowsAffected != int64(len(sentIDs)) {
			flipped, _ = s.flippedSet(sentIDs, "failed")
		}
		for i := range sentTasks {
			t := sentTasks[i]
			if !flipped[t.ID] {
				continue
			}
			t.Status = "failed"
			t.Error = "legacy sent status retired (never dispatched)"
			s.broadcastTaskUpdate(t.AgentID, t)
			s.decPendingTasks(t.AgentID)
		}
		slog.Info("Retired legacy sent tasks", "count", len(sentIDs))
	}

	// Tasks already at the delivery-attempt cap: delivered repeatedly but
	// never acknowledged. Fail them so they stop cycling through the queue.
	var exhaustedTasks []db.Task
	if err := s.db.Where("status = ? AND claimed_at < ? AND acknowledged_at IS NULL AND delivery_attempts >= 3", "running", cutoff).Limit(1000).Find(&exhaustedTasks).Error; err != nil {
		slog.Error("Failed to find stale running tasks past attempt cap", "error", err)
		return false
	}
	fullPage = fullPage || len(exhaustedTasks) == 1000
	exhaustedTasks = s.filterLongSleepTasks(exhaustedTasks, cutoff)
	if len(exhaustedTasks) > 0 {
		exhaustedIDs := make([]uint, len(exhaustedTasks))
		for i, t := range exhaustedTasks {
			exhaustedIDs[i] = t.ID
		}
		// Status guard in the UPDATE (not just the SELECT): a result landing
		// between the two statements must not be stomped — previously a
		// just-completed task could be flipped to "failed" here.
		res := s.withBusyRetryDB("sweep", func() *gorm.DB {
			return s.db.Model(&db.Task{}).Where("id IN ? AND status = ? AND acknowledged_at IS NULL", exhaustedIDs, "running").
				Updates(map[string]interface{}{
					"status": "failed",
					"error":  "delivered but unacknowledged after 3 attempts",
				})
		})
		if res.Error != nil {
			slog.Error("Failed to fail stale running tasks past attempt cap", "count", len(exhaustedIDs), "error", res.Error)
			return false
		}
		flippedEx := make(map[uint]bool, len(exhaustedIDs))
		for _, id := range exhaustedIDs {
			flippedEx[id] = true
		}
		if res.RowsAffected != int64(len(exhaustedIDs)) {
			flippedEx, _ = s.flippedSet(exhaustedIDs, "failed")
		}
		for i := range exhaustedTasks {
			t := exhaustedTasks[i]
			if !flippedEx[t.ID] {
				continue
			}
			t.Status = "failed"
			t.Error = "delivered but unacknowledged after 3 attempts"
			s.broadcastTaskUpdate(t.AgentID, t)
			// Failed tasks leave the pending/running count: without this
			// the in-memory counter leaks until the next reconcile and
			// falsely holds MaxPendingTasksPerAgent slots.
			s.decPendingTasks(t.AgentID)
		}
		slog.Info("Failed stale running tasks past delivery-attempt cap", "count", len(exhaustedIDs))
	}

	var staleTasks []db.Task
	// Select only the columns the requeue pass uses: full rows drag
	// Result/Error blobs and fire a pointless per-row AES-GCM decrypt in
	// Task.AfterFind (same pattern as the beacon-claim path).
	if err := s.db.Where("status = ? AND claimed_at < ? AND acknowledged_at IS NULL AND delivery_attempts < 3", "running", cutoff).
		Select("id, agent_id, claimed_at").Limit(1000).Find(&staleTasks).Error; err != nil {
		slog.Error("Failed to find stale running tasks", "error", err)
		return false
	}
	fullPage = fullPage || len(staleTasks) == 1000
	staleTasks = s.filterLongSleepTasks(staleTasks, cutoff)
	if len(staleTasks) == 0 {
		return fullPage
	}
	taskIDs := make([]uint, len(staleTasks))
	for i, t := range staleTasks {
		taskIDs[i] = t.ID
	}
	// Status guard: without it a result arriving between SELECT and UPDATE
	// flipped a completed task back to "pending", re-delivering and
	// double-executing it on the agent.
	res := s.withBusyRetryDB("sweep", func() *gorm.DB {
		return s.db.Model(&db.Task{}).Where("id IN ? AND status = ? AND acknowledged_at IS NULL", taskIDs, "running").
			Updates(map[string]interface{}{"status": "pending", "claimed_by": "", "claimed_at": time.Time{}, "delivery_attempts": gorm.Expr("delivery_attempts + 1")})
	})
	if res.Error != nil {
		slog.Error("Failed to requeue stale running tasks", "count", len(taskIDs), "error", res.Error)
		return false
	}
	slog.Info("Requeued stale running tasks to pending", "count", res.RowsAffected)
	// Requeued tasks stay in the pending/running count: no dec here.
	return fullPage
}

// filterLongSleepTasks drops tasks whose agent sleeps so long that the
// static cutoff has not actually elapsed for them yet: each task gets
// max(StaleRunningTaskTimeout, 3x its agent's current interval). Agents
// without a row or interval fall back to the static cutoff.
func (s *Server) filterLongSleepTasks(tasks []db.Task, staticCutoff time.Time) []db.Task {
	if len(tasks) == 0 {
		return tasks
	}
	agentIDs := make([]string, 0, len(tasks))
	seen := make(map[string]struct{}, len(tasks))
	for _, t := range tasks {
		if _, ok := seen[t.AgentID]; !ok {
			seen[t.AgentID] = struct{}{}
			agentIDs = append(agentIDs, t.AgentID)
		}
	}
	intervals := make(map[string]int, len(agentIDs))
	var rows []struct {
		ID              string
		CurrentInterval int
	}
	if err := s.db.Model(&db.Implant{}).Where("id IN ?", agentIDs).
		Select("id, current_interval").Scan(&rows).Error; err != nil {
		slog.Warn("Stale sweep: interval lookup failed, using static cutoff", "err", err)
		return tasks
	}
	for _, r := range rows {
		intervals[r.ID] = r.CurrentInterval
	}
	now := time.Now()
	kept := tasks[:0]
	for _, t := range tasks {
		perTaskCutoff := staticCutoff
		if iv := intervals[t.AgentID]; iv > 0 {
			if d := now.Add(-3 * time.Duration(iv) * time.Second); d.Before(perTaskCutoff) {
				perTaskCutoff = d
			}
		}
		if t.ClaimedAt.Before(perTaskCutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

// failStaleAcknowledgedTasks marks tasks that were acknowledged but never produced a result.
// Renewal first: if the agent beaconed after acknowledging (it's alive and
// still working), the deadline is extended by one more window instead of
// failing a healthy long task. At most one renewal per task — a wedged agent
// that beacons forever without finishing still gets failed.
func (s *Server) failStaleAcknowledgedTasks() {
	for pass := 0; pass < maxSweepPasses; pass++ {
		if !s.failStaleAcknowledgedTasksPass() {
			return
		}
	}
}

// failStaleAcknowledgedTasksPass runs one LIMIT page; true means a full page
// was seen and the caller should page again.
func (s *Server) failStaleAcknowledgedTasksPass() bool {
	cutoff := time.Now().Add(-AckedTaskResultTimeout)
	var staleTasks []db.Task
	// Column Select: the pass only needs id/agent_id/acknowledged_at —
	// full rows would drag Result/Error blobs and fire per-row decryption.
	if err := s.db.Where("status = ? AND acknowledged_at IS NOT NULL AND acknowledged_at < ?", "running", cutoff).
		Select("id, agent_id, acknowledged_at").Limit(1000).Find(&staleTasks).Error; err != nil {
		slog.Error("Failed to find stale acknowledged tasks", "error", err)
		return false
	}
	fullPage := len(staleTasks) == 1000
	if len(staleTasks) == 0 {
		return false
	}
	// Agent liveness per involved agent (single query).
	agentIDs := make([]string, 0, len(staleTasks))
	seenAgents := make(map[string]struct{}, len(staleTasks))
	for _, t := range staleTasks {
		if _, ok := seenAgents[t.AgentID]; !ok {
			seenAgents[t.AgentID] = struct{}{}
			agentIDs = append(agentIDs, t.AgentID)
		}
	}
	lastSeen := make(map[string]time.Time, len(agentIDs))
	var implants []struct {
		ID       string
		LastSeen time.Time
	}
	if err := s.db.Model(&db.Implant{}).Where("id IN ?", agentIDs).
		Select("id, last_seen").Scan(&implants).Error; err != nil {
		slog.Warn("Acked sweep: agent lookup failed, failing all stale", "err", err)
	} else {
		for _, im := range implants {
			lastSeen[im.ID] = im.LastSeen
		}
	}
	now := time.Now()
	var failIDs []uint
	var renewIDs []uint
	for _, t := range staleTasks {
		// Renew once: agent alive since ack, and within 2 windows of the ack
		// (bounds wedged agents to a single extension).
		if t.AcknowledgedAt != nil &&
			now.Sub(*t.AcknowledgedAt) < 2*AckedTaskResultTimeout &&
			lastSeen[t.AgentID].After(*t.AcknowledgedAt) {
			renewIDs = append(renewIDs, t.ID)
			continue
		}
		failIDs = append(failIDs, t.ID)
	}
	renewed := 0
	if len(renewIDs) > 0 {
		// One guarded batch UPDATE instead of one busy-retry round trip per
		// task: the status guard still skips rows whose result arrived
		// between SELECT and UPDATE.
		res := s.withBusyRetryDB("sweep", func() *gorm.DB {
			return s.db.Model(&db.Task{}).Where("id IN ? AND status = ?", renewIDs, "running").
				Update("acknowledged_at", now)
		})
		if res.Error != nil {
			slog.Warn("Acked sweep: batch renewal failed", "count", len(renewIDs), "err", res.Error)
		} else {
			renewed = int(res.RowsAffected)
		}
	}
	if renewed > 0 {
		slog.Info("Renewed acked tasks for live agents", "count", renewed)
	}
	if len(failIDs) == 0 {
		return fullPage
	}
	// Status guard plus keep any partial result: the previous unconditional
	// update blanked "result" on tasks whose output arrived between SELECT
	// and UPDATE, destroying real data.
	res := s.withBusyRetryDB("sweep", func() *gorm.DB {
		return s.db.Model(&db.Task{}).Where("id IN ? AND status = ?", failIDs, "running").
			Updates(map[string]interface{}{
				"status": "failed",
				"error":  "task acknowledged but no result received within timeout",
			})
	})
	if res.Error != nil {
		slog.Error("Failed to fail stale acknowledged tasks", "count", len(failIDs), "error", res.Error)
		return false
	}
	flippedAck := make(map[uint]bool, len(failIDs))
	for _, id := range failIDs {
		flippedAck[id] = true
	}
	if res.RowsAffected != int64(len(failIDs)) {
		flippedAck, _ = s.flippedSet(failIDs, "failed")
	}
	failedByID := make(map[uint]db.Task, len(failIDs))
	for _, t := range staleTasks {
		failedByID[t.ID] = t
	}
	for _, id := range failIDs {
		t := failedByID[id]
		if !flippedAck[id] {
			continue
		}
		t.Status = "failed"
		t.Error = "task acknowledged but no result received within timeout"
		t.Result = ""
		s.broadcastTaskUpdate(t.AgentID, t)
		// Failed tasks leave the pending/running count (same leak as the
		// exhausted path had): dec here, reconcile heals any guard race.
		s.decPendingTasks(t.AgentID)
	}
	slog.Info("Failed stale acknowledged tasks with no result", "count", len(failIDs))
	return fullPage
}

// rejectExpiredApprovals auto-rejects approval-gated tasks past their
// expiry: a stale approval prompt is a confused-deputy risk (the world
// changed since creation). Operators are notified once per sweep when any
// were rejected.
func (s *Server) rejectExpiredApprovals() {
	now := time.Now()
	var stale []db.Task
	if err := s.db.Where("status = ? AND approval_expires_at IS NOT NULL AND approval_expires_at < ?",
		TaskStatusPendingApproval, now).Limit(1000).Find(&stale).Error; err != nil {
		slog.Error("Failed to find expired approvals", "error", err)
		return
	}
	if len(stale) == 0 {
		return
	}
	ids := make([]uint, len(stale))
	for i, task := range stale {
		ids[i] = task.ID
	}
	res := s.withBusyRetryDB("sweep", func() *gorm.DB {
		return s.db.Model(&db.Task{}).Where("id IN ? AND status = ?", ids, TaskStatusPendingApproval).
			Updates(map[string]interface{}{"status": "cancelled", "error": approvalExpiredError})
	})
	if res.Error != nil {
		slog.Error("Failed to reject expired approvals", "count", len(ids), "error", res.Error)
		return
	}
	flipped := make(map[uint]bool, len(ids))
	if res.RowsAffected == int64(len(ids)) {
		for _, id := range ids {
			flipped[id] = true
		}
	} else {
		var rows []db.Task
		if err := s.db.Select("id").Where("id IN ? AND status = ? AND error = ?",
			ids, "cancelled", approvalExpiredError).Find(&rows).Error; err == nil {
			for _, row := range rows {
				flipped[row.ID] = true
			}
		}
	}
	for _, task := range stale {
		if !flipped[task.ID] {
			continue
		}
		task.Status = "cancelled"
		task.Error = approvalExpiredError
		s.broadcastTaskUpdate(task.AgentID, task)
		s.decPendingTasks(task.AgentID)
	}
	s.LogAuditRecord(nil, "approval_expired", "task", "", "auto-rejected stale approvals", true, nil)
	s.DispatchNotification(&db.Notification{
		Type: "approval_expired", Title: "Stale task approvals auto-rejected",
		Message:  fmt.Sprintf("%d tasks awaited approval past expiry and were cancelled", len(stale)),
		Severity: "warning",
	})
	slog.Info("Auto-rejected expired approvals", "count", len(stale))
}

// updateTaskBacklogMetrics refreshes per-agent backlog gauges and warns when
// an agent sits above 80% of its pending cap (early signal before the queue
// starts refusing work, including abort injections).
func (s *Server) updateTaskBacklogMetrics() {
	if s.metrics == nil || s.db == nil {
		return
	}
	var rows []struct {
		AgentID string
		Count   int
		Oldest  time.Time
	}
	if err := s.db.Model(&db.Task{}).
		Select("agent_id, COUNT(*) as count, MIN(created_at) as oldest").
		Where("status = ?", "pending").
		Group("agent_id").
		Find(&rows).Error; err != nil {
		slog.Error("Failed to compute task backlog metrics", "err", err)
		return
	}
	seen := make(map[string]struct{}, len(rows))
	now := time.Now()
	for _, r := range rows {
		seen[r.AgentID] = struct{}{}
		s.metrics.TasksPendingByAgent.WithLabelValues(r.AgentID).Set(float64(r.Count))
		s.metrics.OldestPendingSeconds.WithLabelValues(r.AgentID).Set(now.Sub(r.Oldest).Seconds())
		if r.Count >= MaxPendingTasksPerAgent*8/10 {
			slog.Warn("Agent task backlog above 80% of cap", "agent_id", r.AgentID, "pending", r.Count, "cap", MaxPendingTasksPerAgent)
		}
	}
	// Prune series for agents that drained, so deleted-agent labels do not
	// accumulate forever.
	s.backlogAgentsMu.Lock()
	if s.backlogAgents == nil {
		s.backlogAgents = make(map[string]struct{})
	}
	for id := range s.backlogAgents {
		if _, ok := seen[id]; !ok {
			s.metrics.TasksPendingByAgent.DeleteLabelValues(id)
			s.metrics.OldestPendingSeconds.DeleteLabelValues(id)
			delete(s.backlogAgents, id)
		}
	}
	for id := range seen {
		s.backlogAgents[id] = struct{}{}
	}
	s.backlogAgentsMu.Unlock()
}

// reconcilePendingTaskCounts recomputes the in-memory pending task counter from the DB.
func (s *Server) reconcilePendingTaskCounts() {
	var results []struct {
		AgentID string
		Count   int
	}
	// Include pending_approval: createTask counts approval-queued slots and
	// cancel/reject release them, so the recount must use the same semantics
	// or every pass silently shrinks counts and defeats MaxPendingTasksPerAgent.
	if err := s.db.Model(&db.Task{}).
		Select("agent_id, COUNT(*) as count").
		Where("status IN ?", []string{"pending", "running", TaskStatusPendingApproval}).
		Group("agent_id").
		Find(&results).Error; err != nil {
		slog.Error("Failed to reconcile pending task counts", "error", err)
		return
	}
	s.agentPendingTasksMu.Lock()
	clear(s.agentPendingTasks)
	for _, r := range results {
		s.agentPendingTasks[r.AgentID] = r.Count
	}
	s.agentPendingTasksMu.Unlock()
}

// decPendingTasks decrements an agent's pending task counter and removes the
// map entry when it reaches zero, preventing unbounded map growth across the
// server lifetime (and leaked counts after an agent is purged).
func (s *Server) decPendingTasks(agentID string) {
	s.agentPendingTasksMu.Lock()
	if n := s.agentPendingTasks[agentID]; n > 0 {
		if n-1 <= 0 {
			delete(s.agentPendingTasks, agentID)
		} else {
			s.agentPendingTasks[agentID] = n - 1
		}
	}
	s.agentPendingTasksMu.Unlock()
}

// trackPendingTask enforces MaxPendingTasksPerAgent and bumps the in-memory
// counter for tasks created OUTSIDE the standard createTask/dispatch path
// (the AI assistant inserts Task rows directly). Callers must decPendingTasks
// if the subsequent insert fails so the counter never drifts high.
func (s *Server) trackPendingTask(agentID string) error {
	return s.trackPendingTaskReserved(agentID, 0)
}

// trackPendingTaskReserved is trackPendingTask plus extra headroom slots for
// priority injections (abort tasks): cancelling a running task must be able
// to queue its abort even when the backlog is at the normal cap.
func (s *Server) trackPendingTaskReserved(agentID string, extra int) error {
	s.agentPendingTasksMu.Lock()
	defer s.agentPendingTasksMu.Unlock()
	// A Server built without the map (tests, future constructors) must not
	// turn a task insert into a nil-map panic.
	if s.agentPendingTasks == nil {
		s.agentPendingTasks = make(map[string]int)
	}
	if n := s.agentPendingTasks[agentID]; n >= MaxPendingTasksPerAgent+extra {
		return fmt.Errorf("agent %s has %d pending tasks (limit %d)", agentID, n, MaxPendingTasksPerAgent+extra)
	}
	s.agentPendingTasks[agentID]++
	return nil
}

// taskWorkerAcquireTimeout bounds how long a background worker waits for a
// pool slot. Without it, a saturated pool (callbacks/hooks wedged on
// SQLITE_BUSY) parks wg-tracked goroutines forever and stalls graceful
// shutdown inside wg.Wait.
const taskWorkerAcquireTimeout = 30 * time.Second

// runTaskWorker runs fn in a wg-tracked goroutine holding one pool slot. When
// the pool stays saturated past the timeout the work is dropped with a log
// instead of wedging shutdown. Payloads are value-captured by the caller.
func (s *Server) runTaskWorker(what string, fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Task worker panicked", "what", what, "recover", r)
			}
		}()
		select {
		case s.taskWorkerSem <- struct{}{}:
		case <-time.After(taskWorkerAcquireTimeout):
			slog.Warn("Task worker pool saturated, dropping background work", "what", what)
			return
		}
		defer func() { <-s.taskWorkerSem }()
		fn()
	}()
}

// joinUsernames joins a slice of usernames with commas for error messages.
func joinUsernames(names []string) string {
	// #nosec G602 -- the switch is on len(names), so every index below is in range.
	switch len(names) { // #nosec G602
	case 0:
		return ""
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return names[0] + " and " + fmt.Sprintf("%d others", len(names)-1)
	}
}

// isConflictError returns true if the error is an agent conflict (soft-lock).
func isConflictError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "agent conflict:")
}

// respondTaskError writes the appropriate HTTP error for a createTask failure.
// Agent conflicts are surfaced as 409. Validation/policy errors raised before
// any DB write (unknown task type, missing required parameter, opsec block,
// lportfwd disabled, pending-task limit) are client errors (400/403/429) so the
// operator UI can render them instead of a generic 500. Only genuine internal
// failures (DB errors) become 500.
func respondTaskError(c *gin.Context, err error) {
	if isConflictError(err) {
		respondError(c, http.StatusConflict, err.Error())
		return
	}
	if status, ok := clientErrorStatus(err); ok {
		respondError(c, status, err.Error())
		return
	}
	slog.Error("Failed to create task", "error", err)
	respondError(c, http.StatusInternalServerError, "failed to create task")
}

// clientErrorStatus maps the validation/policy errors returned by createTask /
// validateTaskCreation to the correct client HTTP status, keeping them out of
// the 500 bucket.
func clientErrorStatus(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	if errors.Is(err, errCredentialReferenceConflict) || errors.Is(err, errIdempotencyConflict) {
		return http.StatusConflict, true
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "fuse_tripped"):
		return http.StatusTooManyRequests, true
	case strings.Contains(msg, "too many pending tasks"),
		strings.Contains(msg, "pending tasks (limit"):
		return http.StatusTooManyRequests, true
	case strings.Contains(msg, "requires a chrome-tagged agent"),
		strings.Contains(msg, "is not supported on chrome extension agents"),
		strings.Contains(msg, "lportfwd is disabled"),
		strings.Contains(msg, "blocked by adaptive opsec"),
		strings.Contains(msg, "agent expired"),
		strings.Contains(msg, "agent not in scope yet"),
		strings.Contains(msg, "fleet kill-switch is armed"):
		return http.StatusForbidden, true
	case strings.Contains(msg, "unknown task type"),
		strings.Contains(msg, "does not support task type"),
		strings.Contains(msg, "requires 'command' parameter"),
		strings.Contains(msg, "requires 'shell' parameter"),
		strings.Contains(msg, "requires 'path' parameter"),
		strings.Contains(msg, "requires 'data' parameter"),
		strings.Contains(msg, "requires 'expected_sha256' parameter"),
		strings.Contains(msg, "command too long"):
		return http.StatusBadRequest, true
	case strings.Contains(msg, "credential reference"),
		strings.Contains(msg, "credential_id"),
		strings.Contains(msg, "credential has no password"),
		strings.Contains(msg, "credential has expired"),
		strings.Contains(msg, "credential type"),
		strings.Contains(msg, "credential snapshot"):
		return http.StatusBadRequest, true
	}
	return 0, false
}

// agentForDispatch loads every field which can affect dispatch policy. A
// caller-supplied row is trusted only when it came from a complete projection;
// batch/fleet/campaign loads use dispatchAgentColumns below.
func (s *Server) agentForDispatch(agentID string, preloaded *db.Implant) (*db.Implant, error) {
	if preloaded != nil {
		if preloaded.ID == "" {
			preloaded.ID = agentID
		}
		return preloaded, nil
	}
	var agent db.Implant
	if err := s.db.Select(dispatchAgentColumns).Where("id = ?", agentID).First(&agent).Error; err != nil {
		return nil, fmt.Errorf("agent lookup failed for %s: %w", agentID, err)
	}
	return &agent, nil
}

const dispatchAgentColumns = "id, tenant_id, task_types, public_ip, ip, expires_at, engagement_id, kill_date"

// agentExpired is conservative on lookup failure: callers which use this
// boolean for beacon convergence must not mistake an unreadable engagement for
// an unbounded one.
func (s *Server) agentExpired(agent db.Implant) bool {
	engagement, err := s.dispatchEngagement(agent)
	if err != nil {
		return true
	}
	deadline := effectiveDeadlineFor(agent, engagement)
	return deadline != nil && !deadline.IsZero() && time.Now().After(*deadline)
}

func (s *Server) effectiveAgentDeadline(agent db.Implant) *time.Time {
	engagement, err := s.dispatchEngagement(agent)
	if err != nil {
		return nil
	}
	return effectiveDeadlineFor(agent, engagement)
}

// dispatchEngagement fails closed when an associated engagement cannot be
// loaded. A missing association is genuinely unbounded; an unreadable linked
// engagement is a policy outage, not permission to dispatch.
func (s *Server) dispatchEngagement(agent db.Implant) (*db.Engagement, error) {
	return s.dispatchEngagementOn(agent, s.db)
}

func (s *Server) dispatchEngagementOn(agent db.Implant, database *gorm.DB) (*db.Engagement, error) {
	if agent.EngagementID == nil || *agent.EngagementID == 0 {
		return nil, nil
	}
	var engagement db.Engagement
	if err := database.Select("id, tenant_id, starts_at, ends_at, closed_at").
		Where("id = ?", *agent.EngagementID).First(&engagement).Error; err != nil {
		return nil, fmt.Errorf("engagement lookup failed for agent %s: %w", agent.ID, err)
	}
	return &engagement, nil
}

// effectiveDeadlineFor merges the implant deadline with an already-loaded engagement window.
func effectiveDeadlineFor(agent db.Implant, engagement *db.Engagement) *time.Time {
	effective := agent.ExpiresAt
	if engagement == nil {
		return effective
	}
	end := engagement.EndsAt
	if engagement.ClosedAt != nil && engagement.ClosedAt.Before(end) {
		end = *engagement.ClosedAt
	}
	if end.IsZero() {
		return effective
	}
	if effective == nil || end.Before(*effective) {
		return &end
	}
	return effective
}

// engagementNotStarted reports the window an implant must wait for: work is only allowed while the
// engagement it belongs to is open. The end of the window was enforced in an earlier round; the start is
// the symmetric half, and without it an operator can task a host before the exercise has begun - the
// exact thing the agreed window exists to prevent.
func (s *Server) engagementNotStarted(agent db.Implant, engagement *db.Engagement, now time.Time) bool {
	if engagement == nil || engagement.StartsAt.IsZero() {
		return false
	}
	return now.Before(engagement.StartsAt)
}
