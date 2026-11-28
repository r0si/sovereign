package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/config"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/testutil"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// newFakePostgresDB builds a *gorm.DB whose dialector reports "postgres"
// without a live server (automatic ping disabled). The maintenance guards
// must key off driver identity, not connectivity.
func newFakePostgresDB(t *testing.T) *gorm.DB {
	t.Helper()
	conn, err := gorm.Open(postgres.Open("host=127.0.0.1 port=1 user=none dbname=none sslmode=disable connect_timeout=1"),
		&gorm.Config{
			Logger:                 gormlogger.Default.LogMode(gormlogger.Silent),
			DisableAutomaticPing:   true,
			SkipDefaultTransaction: true,
		})
	if err != nil {
		t.Skipf("postgres dialector unavailable: %v", err)
	}
	return conn
}

func operatorCtxFor(method, path string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, nil)
	c.Request.Header.Set("Accept", "application/json")
	c.Set("user", "pg-admin")
	c.Set("user_role", "admin")
	return c, w
}

// TestSQLiteOnlyMaintenanceRefusedOnPostgres proves PostgreSQL maintenance
// reaches the PostgreSQL backup path and fails with actionable configuration
// guidance instead of the retired SQLite-only 501 response.
func TestSQLiteOnlyMaintenanceRefusedOnPostgres(t *testing.T) {
	ginSetTestMode(t)
	s := &Server{db: newFakePostgresDB(t), cfg: config.DefaultConfig()}

	c, w := operatorCtxFor(http.MethodPost, "/settings/db/backup")
	s.handleDBBackup(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("backup: status=%d, want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "encrypted PostgreSQL backups unavailable") {
		t.Fatalf("backup: body lacks PostgreSQL backup guidance: %s", w.Body.String())
	}

	c, w = operatorCtxFor(http.MethodPost, "/settings/db/restore")
	c.Request = httptest.NewRequest(http.MethodPost, "/settings/db/restore", strings.NewReader("type=file"))
	c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.handleDBRestore(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("restore: status=%d, want 500; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PostgreSQL restore unavailable") {
		t.Fatalf("restore: body lacks PostgreSQL restore guidance: %s", w.Body.String())
	}
}

// TestDBVacuumRunsAnalyzeOnPostgres pins the intended behavior: the maintenance
// endpoint works on PostgreSQL (the production driver), running VACUUM ANALYZE
// and reporting a real size, instead of answering 501 like a driver it no
// longer supports. Skipped when no PostgreSQL is reachable.
func TestDBVacuumRunsAnalyzeOnPostgres(t *testing.T) {
	ginSetTestMode(t)
	gdb, err := db.InitDBWithDriver("postgres", testPostgresDSN, "", slog.LevelWarn, 1, 1, time.Minute)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	s := &Server{db: gdb, cfg: config.DefaultConfig()}

	c, w := operatorCtxFor(http.MethodPost, "/settings/maintenance/vacuum")
	s.handleDBVacuum(c)
	if w.Code != http.StatusOK {
		t.Fatalf("vacuum on postgres = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "SQLite only") {
		t.Fatalf("vacuum still refuses postgres: %s", w.Body.String())
	}
	// size is advisory but must be reported as a field.
	if !strings.Contains(w.Body.String(), "\"size\"") {
		t.Fatalf("vacuum response missing size field: %s", w.Body.String())
	}
}

// TestBackupManagerPostgresRequiresConfiguration proves the scheduled path no
// longer refuses non-SQLite databases outright; it requires PostgreSQL backup
// configuration (DSN/tools) instead.
func TestBackupManagerPostgresRequiresConfiguration(t *testing.T) {
	bm := &BackupManager{db: newFakePostgresDB(t), backupDir: t.TempDir()}
	if _, _, err := bm.createBackup(); err == nil {
		t.Fatal("createBackup succeeded without PostgreSQL backup configuration")
	}
	if err := bm.Start("daily"); err == nil {
		t.Fatal("Start succeeded without PostgreSQL backup configuration")
	}
}

// TestSQLiteMaintenanceStillWorks guards the guard: SQLite deployments keep the
// full backup path.
func TestSQLiteMaintenanceStillWorks(t *testing.T) {
	ginSetTestMode(t)
	database := testutil.SetupTestDB(t)
	if !isSQLiteDB(database) {
		t.Skip("test database is not SQLite")
	}
	cfg := config.DefaultConfig()
	cfg.Server.DataDir = t.TempDir()
	s := &Server{db: database, cfg: cfg}

	c, w := operatorCtxFor(http.MethodPost, "/settings/db/backup")
	if !s.requireSQLiteDB(c) {
		t.Fatalf("SQLite deployment refused maintenance: %s", w.Body.String())
	}
}

// TestIsSQLiteDBHandlesNil guards the helper against a nil handle (callers
// include bare test servers).
func TestIsSQLiteDBHandlesNil(t *testing.T) {
	if isSQLiteDB(nil) {
		t.Fatal("nil db must not be treated as SQLite")
	}
}

// keep time imported for the gorm open options above on all build paths.
var _ = time.Second
