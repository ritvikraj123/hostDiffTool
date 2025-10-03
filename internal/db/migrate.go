package db

import (
	"database/sql"
	"fmt"
)

// Migrate runs database migrations
func Migrate(db *sql.DB) error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id INTEGER NOT NULL,
			observed_at DATETIME NOT NULL,
			raw_json TEXT NOT NULL,
			FOREIGN KEY (host_id) REFERENCES hosts (id),
			UNIQUE(host_id, observed_at)
		)`,
		`CREATE TABLE IF NOT EXISTS services (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			snapshot_id INTEGER NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			service_name TEXT,
			product TEXT,
			vendor TEXT,
			version TEXT,
			vuln_ids TEXT,
			FOREIGN KEY (snapshot_id) REFERENCES snapshots (id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_snapshots_host_id ON snapshots (host_id)`,
		`CREATE INDEX IF NOT EXISTS idx_snapshots_observed_at ON snapshots (observed_at)`,
		`CREATE INDEX IF NOT EXISTS idx_services_snapshot_id ON services (snapshot_id)`,
		`CREATE INDEX IF NOT EXISTS idx_services_port_protocol ON services (port, protocol)`,
	}

	for i, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	return nil
}
