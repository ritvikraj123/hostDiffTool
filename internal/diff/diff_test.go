package diff

import (
	"testing"

	"github.com/example/hostdiff/internal/model"
)

func TestCompareSnapshots(t *testing.T) {
	tests := []struct {
		name     string
		left     map[model.ServiceKey]model.ServiceData
		right    map[model.ServiceKey]model.ServiceData
		expected model.DiffResult
	}{
		{
			name: "only opened port",
			left:  map[model.ServiceKey]model.ServiceData{},
			right: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.18.0",
				},
			},
			expected: model.DiffResult{
				OpenedPorts:   []int{80},
				ClosedPorts:   []int{},
				AddedServices: map[string]model.ServiceData{
					"80/TCP": {
						ServiceName: "http",
						Product:     "nginx",
						Vendor:      "nginx",
						Version:     "1.18.0",
					},
				},
				RemovedServices: map[string]model.ServiceData{},
				ServiceChanges:  map[string]model.ServiceChange{},
			},
		},
		{
			name: "only closed port",
			left: map[model.ServiceKey]model.ServiceData{
				{Port: 22, Protocol: "tcp"}: {
					ServiceName: "ssh",
					Product:     "openssh",
					Vendor:      "openssh",
					Version:     "8.2p1",
				},
			},
			right: map[model.ServiceKey]model.ServiceData{},
			expected: model.DiffResult{
				OpenedPorts:   []int{},
				ClosedPorts:   []int{22},
				AddedServices: map[string]model.ServiceData{},
				RemovedServices: map[string]model.ServiceData{
					"22/TCP": {
						ServiceName: "ssh",
						Product:     "openssh",
						Vendor:      "openssh",
						Version:     "8.2p1",
					},
				},
				ServiceChanges: map[string]model.ServiceChange{},
			},
		},
		{
			name: "version change",
			left: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.18.0",
				},
			},
			right: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.20.0",
				},
			},
			expected: model.DiffResult{
				OpenedPorts:   []int{},
				ClosedPorts:   []int{},
				AddedServices: map[string]model.ServiceData{},
				RemovedServices: map[string]model.ServiceData{},
				ServiceChanges: map[string]model.ServiceChange{
					"80/TCP": {
						Port:           80,
						Protocol:       "TCP",
						VendorChanged:  false,
						ProductChanged: false,
						VersionChanged: true,
						VulnsAdded:     model.VulnIDs{},
						VulnsRemoved:   model.VulnIDs{},
						OldData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx",
							Vendor:      "nginx",
							Version:     "1.18.0",
						},
						NewData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx",
							Vendor:      "nginx",
							Version:     "1.20.0",
						},
					},
				},
			},
		},
		{
			name: "vulnerability added and removed",
			left: map[model.ServiceKey]model.ServiceData{
				{Port: 22, Protocol: "tcp"}: {
					ServiceName: "ssh",
					Product:     "openssh",
					Vendor:      "openssh",
					Version:     "8.2p1",
					VulnIDs:     model.VulnIDs{"CVE-2023-99992"},
				},
			},
			right: map[model.ServiceKey]model.ServiceData{
				{Port: 22, Protocol: "tcp"}: {
					ServiceName: "ssh",
					Product:     "openssh",
					Vendor:      "openssh",
					Version:     "8.2p1",
					VulnIDs:     model.VulnIDs{"CVE-2024-1234"},
				},
			},
			expected: model.DiffResult{
				OpenedPorts:   []int{},
				ClosedPorts:   []int{},
				AddedServices: map[string]model.ServiceData{},
				RemovedServices: map[string]model.ServiceData{},
				ServiceChanges: map[string]model.ServiceChange{
					"22/TCP": {
						Port:           22,
						Protocol:       "TCP",
						VendorChanged:  false,
						ProductChanged: false,
						VersionChanged: false,
						VulnsAdded:     model.VulnIDs{"CVE-2024-1234"},
						VulnsRemoved:   model.VulnIDs{"CVE-2023-99992"},
						OldData: model.ServiceData{
							ServiceName: "ssh",
							Product:     "openssh",
							Vendor:      "openssh",
							Version:     "8.2p1",
							VulnIDs:     model.VulnIDs{"CVE-2023-99992"},
						},
						NewData: model.ServiceData{
							ServiceName: "ssh",
							Product:     "openssh",
							Vendor:      "openssh",
							Version:     "8.2p1",
							VulnIDs:     model.VulnIDs{"CVE-2024-1234"},
						},
					},
				},
			},
		},
		{
			name: "multiple services including same port different protocol",
			left: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.18.0",
				},
				{Port: 80, Protocol: "udp"}: {
					ServiceName: "dns",
					Product:     "bind",
					Vendor:      "isc",
					Version:     "9.16.0",
				},
				{Port: 22, Protocol: "tcp"}: {
					ServiceName: "ssh",
					Product:     "openssh",
					Vendor:      "openssh",
					Version:     "8.2p1",
				},
			},
			right: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.20.0", // version changed
				},
				{Port: 80, Protocol: "udp"}: {
					ServiceName: "dns",
					Product:     "bind",
					Vendor:      "isc",
					Version:     "9.16.0",
				},
				{Port: 443, Protocol: "tcp"}: { // new service
					ServiceName: "https",
					Product:     "nginx",
					Vendor:      "nginx",
					Version:     "1.20.0",
				},
			},
			expected: model.DiffResult{
				OpenedPorts:   []int{443},
				ClosedPorts:   []int{22},
				AddedServices: map[string]model.ServiceData{
					"443/TCP": {
						ServiceName: "https",
						Product:     "nginx",
						Vendor:      "nginx",
						Version:     "1.20.0",
					},
				},
				RemovedServices: map[string]model.ServiceData{
					"22/TCP": {
						ServiceName: "ssh",
						Product:     "openssh",
						Vendor:      "openssh",
						Version:     "8.2p1",
					},
				},
				ServiceChanges: map[string]model.ServiceChange{
					"80/TCP": {
						Port:           80,
						Protocol:       "TCP",
						VendorChanged:  false,
						ProductChanged: false,
						VersionChanged: true,
						VulnsAdded:     model.VulnIDs{},
						VulnsRemoved:   model.VulnIDs{},
						OldData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx",
							Vendor:      "nginx",
							Version:     "1.18.0",
						},
						NewData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx",
							Vendor:      "nginx",
							Version:     "1.20.0",
						},
					},
				},
			},
		},
		{
			name: "fields normalized",
			left: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "Nginx", // mixed case
					Vendor:      "Nginx", // mixed case
					Version:     "1.18.0",
					VulnIDs:     model.VulnIDs{"cve-2023-99992"}, // lowercase
				},
			},
			right: map[model.ServiceKey]model.ServiceData{
				{Port: 80, Protocol: "tcp"}: {
					ServiceName: "http",
					Product:     "nginx", // lowercase
					Vendor:      "nginx", // lowercase
					Version:     "1.20.0",
					VulnIDs:     model.VulnIDs{"CVE-2024-1234"}, // uppercase
				},
			},
			expected: model.DiffResult{
				OpenedPorts:   []int{},
				ClosedPorts:   []int{},
				AddedServices: map[string]model.ServiceData{},
				RemovedServices: map[string]model.ServiceData{},
				ServiceChanges: map[string]model.ServiceChange{
					"80/TCP": {
						Port:           80,
						Protocol:       "TCP",
						VendorChanged:  false,
						ProductChanged: false,
						VersionChanged: true,
						VulnsAdded:     model.VulnIDs{"CVE-2024-1234"},
						VulnsRemoved:   model.VulnIDs{"CVE-2023-99992"},
						OldData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx", // normalized to lowercase
							Vendor:      "nginx", // normalized to lowercase
							Version:     "1.18.0",
							VulnIDs:     model.VulnIDs{"CVE-2023-99992"}, // normalized to uppercase
						},
						NewData: model.ServiceData{
							ServiceName: "http",
							Product:     "nginx",
							Vendor:      "nginx",
							Version:     "1.20.0",
							VulnIDs:     model.VulnIDs{"CVE-2024-1234"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareSnapshots(tt.left, tt.right)
			
			// Check opened ports
			if !equalIntSlices(result.OpenedPorts, tt.expected.OpenedPorts) {
				t.Errorf("OpenedPorts = %v, want %v", result.OpenedPorts, tt.expected.OpenedPorts)
			}
			
			// Check closed ports
			if !equalIntSlices(result.ClosedPorts, tt.expected.ClosedPorts) {
				t.Errorf("ClosedPorts = %v, want %v", result.ClosedPorts, tt.expected.ClosedPorts)
			}
			
			// Check added services
			if !equalServiceDataMaps(result.AddedServices, tt.expected.AddedServices) {
				t.Errorf("AddedServices = %v, want %v", result.AddedServices, tt.expected.AddedServices)
			}
			
			// Check removed services
			if !equalServiceDataMaps(result.RemovedServices, tt.expected.RemovedServices) {
				t.Errorf("RemovedServices = %v, want %v", result.RemovedServices, tt.expected.RemovedServices)
			}
			
			// Check service changes
			if !equalServiceChangeMaps(result.ServiceChanges, tt.expected.ServiceChanges) {
				t.Errorf("ServiceChanges = %v, want %v", result.ServiceChanges, tt.expected.ServiceChanges)
			}
		})
	}
}

func TestParseIPFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		expected string
		hasError bool
	}{
		{"host_192.168.1.1_2025-09-10T03-00-00Z.json", "192.168.1.1", false},
		{"host_10.0.0.1_2025-09-15T08-49-45Z.json", "10.0.0.1", false},
		{"invalid.json", "", true},
		{"host_.json", "", true},
		{"host_ip_timestamp.json", "ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result, err := ParseIPFromFilename(tt.filename)
			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("got %s, want %s", result, tt.expected)
				}
			}
		})
	}
}

func TestParseTimestampFromFilename(t *testing.T) {
	tests := []struct {
		filename string
		expected string
		hasError bool
	}{
		{"host_192.168.1.1_2025-09-10T03-00-00Z.json", "2025-09-10T03:00:00Z", false},
		{"host_10.0.0.1_2025-09-15T08-49-45Z.json", "2025-09-15T08:49:45Z", false},
		{"invalid.json", "", true},
		{"host_ip_.json", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result, err := ParseTimestampFromFilename(tt.filename)
			if tt.hasError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("got %s, want %s", result, tt.expected)
				}
			}
		})
	}
}

// Helper functions for testing
func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalServiceDataMaps(a, b map[string]model.ServiceData) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !equalServiceData(v, bv) {
			return false
		}
	}
	return true
}

func equalServiceData(a, b model.ServiceData) bool {
	return a.ServiceName == b.ServiceName &&
		a.Product == b.Product &&
		a.Vendor == b.Vendor &&
		a.Version == b.Version &&
		equalVulnIDs(a.VulnIDs, b.VulnIDs)
}

func equalVulnIDs(a, b model.VulnIDs) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalServiceChangeMaps(a, b map[string]model.ServiceChange) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !equalServiceChange(v, bv) {
			return false
		}
	}
	return true
}

func equalServiceChange(a, b model.ServiceChange) bool {
	return a.Port == b.Port &&
		a.Protocol == b.Protocol &&
		a.VendorChanged == b.VendorChanged &&
		a.ProductChanged == b.ProductChanged &&
		a.VersionChanged == b.VersionChanged &&
		equalVulnIDs(a.VulnsAdded, b.VulnsAdded) &&
		equalVulnIDs(a.VulnsRemoved, b.VulnsRemoved) &&
		equalServiceData(a.OldData, b.OldData) &&
		equalServiceData(a.NewData, b.NewData)
}
