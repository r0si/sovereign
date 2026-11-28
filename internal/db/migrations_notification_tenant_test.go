package db

import "testing"

func TestNotificationTenantMigration(t *testing.T) {
	database := openTestDB(t)
	for _, table := range []string{"notifications", "notification_routes"} {
		if err := database.Exec("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY, name TEXT)").Error; err != nil {
			t.Fatal(err)
		}
		if err := database.Exec("INSERT INTO " + table + " (id, name) VALUES (1, 'legacy')").Error; err != nil {
			t.Fatal(err)
		}
	}
	mig := findMigration(t, "2026-11-28-notification-tenant-scope")
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, table := range []string{"notifications", "notification_routes"} {
		var tenantID *uint
		if err := database.Table(table).Select("tenant_id").Where("id = ?", 1).Scan(&tenantID).Error; err != nil {
			t.Fatal(err)
		}
		if tenantID == nil || *tenantID != 0 {
			t.Fatalf("%s legacy tenant = %v, want 0", table, tenantID)
		}
		if !database.Migrator().HasIndex(table, "idx_"+table+"_tenant_id") {
			t.Fatalf("%s tenant index missing", table)
		}
	}
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := mig.Rollback(database); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	for _, table := range []string{"notifications", "notification_routes"} {
		if database.Migrator().HasColumn(table, "tenant_id") {
			t.Fatalf("%s tenant_id survived rollback", table)
		}
	}
}

func TestNotificationTenantMigrationSkipsMissingTables(t *testing.T) {
	database := openTestDB(t)
	mig := findMigration(t, "2026-11-28-notification-tenant-scope")
	if err := mig.Migrate(database); err != nil {
		t.Fatalf("empty database migrate: %v", err)
	}
}
