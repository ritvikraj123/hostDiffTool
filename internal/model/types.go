package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Host represents a host identified by IP
type Host struct {
	ID        int       `json:"id"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

// Snapshot represents a host snapshot at a specific time
type Snapshot struct {
	ID         int       `json:"id"`
	HostID     int       `json:"host_id"`
	ObservedAt time.Time `json:"observed_at"`
	RawJSON    string    `json:"raw_json"`
}

// Service represents a service running on a host
type Service struct {
	ID          int      `json:"id"`
	SnapshotID  int      `json:"snapshot_id"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	ServiceName string   `json:"service_name"`
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor"`
	Version     string   `json:"version"`
	VulnIDs     VulnIDs  `json:"vuln_ids"`
}

// VulnIDs represents a list of vulnerability IDs
type VulnIDs []string

// Scan implements the sql.Scanner interface
func (v *VulnIDs) Scan(value interface{}) error {
	if value == nil {
		*v = nil
		return nil
	}
	
	switch val := value.(type) {
	case string:
		return json.Unmarshal([]byte(val), v)
	case []byte:
		return json.Unmarshal(val, v)
	default:
		return fmt.Errorf("cannot scan %T into VulnIDs", value)
	}
}

// Value implements the driver.Valuer interface
func (v VulnIDs) Value() (driver.Value, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// ServiceKey represents a unique service identifier
type ServiceKey struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// Canonicalize normalizes the service key for comparison
func (sk ServiceKey) Canonicalize() ServiceKey {
	return ServiceKey{
		Port:     sk.Port,
		Protocol: strings.ToUpper(sk.Protocol),
	}
}

// ServiceData represents the data for a service
type ServiceData struct {
	ServiceName string   `json:"service_name"`
	Product     string   `json:"product"`
	Vendor      string   `json:"vendor"`
	Version     string   `json:"version"`
	VulnIDs     VulnIDs  `json:"vuln_ids"`
}

// Canonicalize normalizes the service data for comparison
func (sd ServiceData) Canonicalize() ServiceData {
	return ServiceData{
		ServiceName: sd.ServiceName,
		Product:     strings.ToLower(sd.Product),
		Vendor:      strings.ToLower(sd.Vendor),
		Version:     sd.Version,
		VulnIDs:     sd.VulnIDs.Canonicalize(),
	}
}

// Canonicalize normalizes vulnerability IDs
func (v VulnIDs) Canonicalize() VulnIDs {
	seen := make(map[string]bool)
	var result VulnIDs
	for _, vuln := range v {
		normalized := strings.ToUpper(strings.TrimSpace(vuln))
		if normalized != "" && !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}
	return result
}

// DiffResult represents the result of comparing two snapshots
type DiffResult struct {
	LeftSnapshotID  int                    `json:"left_snapshot_id"`
	RightSnapshotID int                    `json:"right_snapshot_id"`
	OpenedPorts     []int                  `json:"opened_ports"`
	ClosedPorts     []int                  `json:"closed_ports"`
	AddedServices   map[string]ServiceData `json:"added_services"`
	RemovedServices map[string]ServiceData `json:"removed_services"`
	ServiceChanges  map[string]ServiceChange `json:"service_changes"`
}

// ServiceChange represents changes to a service
type ServiceChange struct {
	Port           int      `json:"port"`
	Protocol       string   `json:"protocol"`
	VendorChanged  bool     `json:"vendor_changed"`
	ProductChanged bool     `json:"product_changed"`
	VersionChanged bool     `json:"version_changed"`
	VulnsAdded     VulnIDs  `json:"vulns_added"`
	VulnsRemoved   VulnIDs  `json:"vulns_removed"`
	OldData        ServiceData `json:"old_data"`
	NewData        ServiceData `json:"new_data"`
}

// HostSummary represents a summary of a host
type HostSummary struct {
	IP            string `json:"ip"`
	SnapshotCount int    `json:"snapshot_count"`
}

// SnapshotSummary represents a summary of a snapshot
type SnapshotSummary struct {
	ID         int       `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
}
