package db

import "testing"

func TestGeneratedReportTenantMigration(t *testing.T) {
	database := openTestDB(t)
	if err := database.Exec(`CREATE TABLE generated_reports (id INTEGER PRIMARY KEY, name TEXT, created_at DATETIME)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(`INSERT INTO generated_reports (id, name) VALUES (1, 'legacy')`).Error; err != nil {
		t.Fatal(err)
	}
	mig := findMigration(t, "2026-11-28-generated-report-tenant")
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var tenantID *uint
	if err := database.Table("generated_reports").Select("tenant_id").Where("id = ?", 1).Scan(&tenantID).Error; err != nil {
		t.Fatal(err)
	}
	if tenantID == nil || *tenantID != 0 {
		t.Fatalf("legacy report tenant = %v, want 0", tenantID)
	}
	if !database.Migrator().HasIndex("generated_reports", "idx_generated_reports_tenant_created") {
		t.Fatal("tenant/created index missing")
	}
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func TestGeneratedReportTenantMigrationRollback(t *testing.T) {
	database := openTestDB(t)
	if err := database.Exec(`CREATE TABLE generated_reports (id INTEGER PRIMARY KEY, name TEXT, created_at DATETIME)`).Error; err != nil {
		t.Fatal(err)
	}
	mig := findMigration(t, "2026-11-28-generated-report-tenant")
	if err := mig.Migrate(database); err != nil {
		t.Fatal(err)
	}
	if err := mig.Rollback(database); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if database.Migrator().HasColumn("generated_reports", "tenant_id") {
		t.Fatal("tenant_id survived rollback")
	}
}

func TestGeneratedReportTenantMigrationSkipsMissingTable(t *testing.T) {
	database := openTestDB(t)
	mig := findMigration(t, "2026-11-28-generated-report-tenant")
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("empty database migrate: %v", err)
	}
}
