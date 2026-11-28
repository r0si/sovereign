package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/server/middleware"
)

func (s *Server) createSession(token string, userID uint, ip, userAgent, deviceFingerprint string, maxAge int) error {
	hash := middleware.TokenHash(token)
	sess := db.UserSession{
		UserID:            userID,
		TokenHash:         hash,
		IP:                ip,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
		ExpiresAt:         time.Now().Add(time.Duration(maxAge) * time.Second),
	}
	if err := s.db.Create(&sess).Error; err != nil {
		slog.Error("Failed to create session", "user_id", userID, "err", err)
		return err
	}
	return nil
}

// enforceSessionCap evicts the oldest live sessions beyond
// auth.session_max_concurrent (0 = unlimited). Called at login, after the
// new session row exists, so the fresh login always survives. Returns the
// number evicted (audited by the caller).
func (s *Server) enforceSessionCap(userID uint, maxConcurrent int) int {
	if maxConcurrent < 1 {
		return 0
	}
	var ids []uint
	if err := s.db.Model(&db.UserSession{}).
		Where("user_id = ? AND revoked_at <= ? AND expires_at > ?", userID, time.Unix(0, 0), time.Now()).
		Order("id ASC").Pluck("id", &ids).Error; err != nil {
		slog.Error("Failed to list sessions for cap enforcement", "user_id", userID, "err", err)
		return 0
	}
	if len(ids) <= maxConcurrent {
		return 0
	}
	victims := ids[:len(ids)-maxConcurrent]
	if err := s.db.Model(&db.UserSession{}).Where("id IN ?", victims).Update("revoked_at", time.Now()).Error; err != nil {
		slog.Error("Failed to evict excess sessions", "user_id", userID, "err", err)
		return 0
	}
	return len(victims)
}

// isKnownLoginIP reports whether the user has ever logged in from ip
// (any session row, any state). First sighting is audit-worthy.
func (s *Server) isKnownLoginIP(userID uint, ip string) bool {
	if ip == "" {
		return true
	}
	var n int64
	if err := s.db.Model(&db.UserSession{}).Where("user_id = ? AND ip = ?", userID, ip).Count(&n).Error; err != nil {
		slog.Error("Failed to check login IP history", "user_id", userID, "err", err)
		return true // fail open on DB error: login must not break
	}
	return n > 0
}

func (s *Server) revokeSession(token string) bool {
	hash := middleware.TokenHash(token)
	if err := s.db.Model(&db.UserSession{}).Where("token_hash = ?", hash).
		Update("revoked_at", time.Now()).Error; err != nil {
		slog.Error("Failed to revoke session", "err", err)
		return false
	}
	return true
}

// revokeAllUserSessions revokes every live session for userID. Returns the
// underlying error so security-critical callers (force-logout, disable)
// can fail closed instead of leaving resurrectable session rows behind.
func (s *Server) revokeAllUserSessions(userID uint) error {
	if err := s.db.Model(&db.UserSession{}).Where("user_id = ? AND revoked_at = ?", userID, time.Time{}).
		Update("revoked_at", time.Now()).Error; err != nil {
		slog.Error("Failed to revoke all user sessions", "user_id", userID, "err", err)
		return err
	}
	return nil
}

// isSessionRevoked reports whether a session token was revoked. A database
// error is returned (never swallowed): callers must fail closed (503), so a
// wedged database cannot resurrect logged-out sessions.
func (s *Server) isSessionRevoked(token string) (bool, error) {
	hash := middleware.TokenHash(token)
	var count int64
	if err := s.db.Model(&db.UserSession{}).
		Where("token_hash = ? AND revoked_at > ?", hash, time.Time{}).
		Count(&count).Error; err != nil {
		slog.Error("Failed to check if session is revoked", "err", err)
		return false, err
	}
	return count > 0, nil
}

func (s *Server) resolveSessionTarget(c *gin.Context, userID string) (uint, bool) {
	targetID, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		respondError(c, http.StatusBadRequest, "Invalid user ID")
		return 0, false
	}
	if c.GetString("user_role") == db.RoleAdmin {
		if middleware.IsScopedAPIKey(c) {
			respondError(c, http.StatusForbidden, "scoped API key denied")
			return 0, false
		}
		var target db.User
		if !s.findTenantOrFail(c, &target, userID, "user") {
			return 0, false
		}
		return uint(targetID), true
	}
	requesterID, ok := currentUserID(c)
	if !ok || requesterID != uint(targetID) {
		respondError(c, http.StatusForbidden, "Permission denied")
		return 0, false
	}
	return uint(targetID), true
}

func (s *Server) handleListUserSessions(c *gin.Context) {
	targetID, ok := s.resolveSessionTarget(c, c.Param("id"))
	if !ok {
		return
	}
	var sessions []db.UserSession
	if err := s.db.Where("user_id = ? AND revoked_at = ? AND expires_at > ?", targetID, time.Time{}, time.Now()).
		Order("created_at DESC").Find(&sessions).Error; err != nil {
		slog.Error("Failed to list user sessions", "error", err)
		respondError(c, http.StatusInternalServerError, "Failed to list sessions")
		return
	}
	respond(c, gin.H{"sessions": sessions})
}

func (s *Server) handleRevokeSession(c *gin.Context) {
	userID := c.Param("id")
	sessionID := c.Param("sessionId")
	targetID, ok := s.resolveSessionTarget(c, userID)
	if !ok {
		return
	}

	var session db.UserSession
	if err := s.db.First(&session, "id = ?", sessionID).Error; err != nil {
		respondError(c, http.StatusNotFound, "Session not found")
		return
	}
	if session.UserID != targetID {
		if c.GetString("user_role") == db.RoleAdmin {
			respondError(c, http.StatusNotFound, "Session not found")
		} else {
			respondError(c, http.StatusForbidden, "Permission denied")
		}
		return
	}
	if err := s.db.Model(&db.UserSession{}).Where("id = ? AND user_id = ?", sessionID, targetID).
		Update("revoked_at", time.Now()).Error; err != nil {
		s.LogAuditRecord(c, "session_revoke", "user", userID,
			fmt.Sprintf("Failed to revoke session %s for user %s", sessionID, userID), false, err)
		respondError(c, http.StatusInternalServerError, "Failed to revoke session")
		return
	}
	s.LogAuditRecord(c, "session_revoke", "user", userID,
		fmt.Sprintf("Revoked session %s (ip=%s)", sessionID, session.IP), true, nil)
	respond(c, gin.H{"message": "Session revoked"})
}

func (s *Server) handleRevokeAllUserSessions(c *gin.Context) {
	userID := c.Param("id")
	if c.GetString("user_role") != db.RoleAdmin {
		respondError(c, http.StatusForbidden, "Permission denied")
		return
	}
	targetID, ok := s.resolveSessionTarget(c, userID)
	if !ok {
		return
	}
	result := s.db.Model(&db.UserSession{}).
		Where("user_id = ? AND revoked_at = ?", targetID, time.Time{}).
		Update("revoked_at", time.Now())
	if err := result.Error; err != nil {
		s.LogAuditRecord(c, "session_revoke_all", "user", userID,
			fmt.Sprintf("Failed to revoke all sessions for user %s", userID), false, err)
		respondError(c, http.StatusInternalServerError, "Failed to revoke sessions")
		return
	}
	s.LogAuditRecord(c, "session_revoke_all", "user", userID,
		fmt.Sprintf("Revoked %d session(s) for user %s", result.RowsAffected, userID), true, nil)
	respond(c, gin.H{
		"message": fmt.Sprintf("Revoked %d sessions", result.RowsAffected),
	})
}
