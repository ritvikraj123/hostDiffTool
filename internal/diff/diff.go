package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/example/hostdiff/internal/model"
)

// CompareSnapshots finds differences between two host snapshots
func CompareSnapshots(old, new map[model.ServiceKey]model.ServiceData) model.DiffResult {
	result := model.DiffResult{
		AddedServices:   make(map[string]model.ServiceData),
		RemovedServices: make(map[string]model.ServiceData),
		ServiceChanges:  make(map[string]model.ServiceChange),
	}

	// Track all ports
	oldPorts := make(map[int]bool)
	newPorts := make(map[int]bool)

	// Process old snapshot
	for key, data := range old {
		normKey := key.Canonicalize()
		normData := data.Canonicalize()
		oldPorts[key.Port] = true
		
		// Check if service exists in new
		if newData, exists := new[key]; exists {
			normNewData := newData.Canonicalize()
			
			// Check for changes
			change := model.ServiceChange{
				Port:     key.Port,
				Protocol: normKey.Protocol,
				OldData:  normData,
				NewData:  normNewData,
			}
			
			if normData.Vendor != normNewData.Vendor {
				change.VendorChanged = true
			}
			if normData.Product != normNewData.Product {
				change.ProductChanged = true
			}
			if normData.Version != normNewData.Version {
				change.VersionChanged = true
			}
			
			// Compare vulnerabilities
			change.VulnsAdded, change.VulnsRemoved = compareVulns(normData.VulnIDs, normNewData.VulnIDs)
			
			// Only include if there are actual changes
			if change.VendorChanged || change.ProductChanged || change.VersionChanged || 
			   len(change.VulnsAdded) > 0 || len(change.VulnsRemoved) > 0 {
				keyStr := fmt.Sprintf("%d/%s", key.Port, normKey.Protocol)
				result.ServiceChanges[keyStr] = change
			}
		} else {
			// Service was removed
			keyStr := fmt.Sprintf("%d/%s", key.Port, normKey.Protocol)
			result.RemovedServices[keyStr] = normData
		}
	}

	// Process new snapshot
	for key, data := range new {
		normKey := key.Canonicalize()
		normData := data.Canonicalize()
		newPorts[key.Port] = true
		
		// Check if service exists in old
		if _, exists := old[key]; !exists {
			// Service was added
			keyStr := fmt.Sprintf("%d/%s", key.Port, normKey.Protocol)
			result.AddedServices[keyStr] = normData
		}
	}

	// Calculate opened and closed ports
	for port := range newPorts {
		if !oldPorts[port] {
			result.OpenedPorts = append(result.OpenedPorts, port)
		}
	}
	
	for port := range oldPorts {
		if !newPorts[port] {
			result.ClosedPorts = append(result.ClosedPorts, port)
		}
	}

	// Sort port lists
	sort.Ints(result.OpenedPorts)
	sort.Ints(result.ClosedPorts)

	return result
}

// compareVulns finds added and removed vulnerabilities between two lists
func compareVulns(oldVulns, newVulns model.VulnIDs) (added, removed model.VulnIDs) {
	oldSet := make(map[string]bool)
	newSet := make(map[string]bool)
	
	for _, vuln := range oldVulns {
		oldSet[vuln] = true
	}
	
	for _, vuln := range newVulns {
		newSet[vuln] = true
	}
	
	// Find added vulnerabilities
	for vuln := range newSet {
		if !oldSet[vuln] {
			added = append(added, vuln)
		}
	}
	
	// Find removed vulnerabilities
	for vuln := range oldSet {
		if !newSet[vuln] {
			removed = append(removed, vuln)
		}
	}
	
	// Sort for consistent output
	sort.Strings(added)
	sort.Strings(removed)
	
	return added, removed
}

// ParseServicesFromJSON extracts service data from JSON snapshot
func ParseServicesFromJSON(data map[string]interface{}) (map[model.ServiceKey]model.ServiceData, error) {
	services := make(map[model.ServiceKey]model.ServiceData)
	
	// Try different possible keys for services
	possibleKeys := []string{"services", "ports", "open_ports"}
	var svcList []interface{}
	
	for _, key := range possibleKeys {
		if val, exists := data[key]; exists {
			if list, ok := val.([]interface{}); ok {
				svcList = list
				break
			} else if dict, ok := val.(map[string]interface{}); ok {
				// Convert map to list
				for _, svc := range dict {
					svcList = append(svcList, svc)
				}
				break
			}
		}
	}
	
	if svcList == nil {
		return services, nil
	}
	
	for _, svcInterface := range svcList {
		svcMap, ok := svcInterface.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Extract port
		port, ok := getIntFromInterface(svcMap["port"])
		if !ok {
			continue
		}
		
		// Extract protocol
		protocol, ok := svcMap["protocol"].(string)
		if !ok {
			continue
		}
		
		key := model.ServiceKey{Port: port, Protocol: protocol}
		
		// Extract service data
		svcData := model.ServiceData{}
		
		if name, ok := svcMap["service_name"].(string); ok {
			svcData.ServiceName = name
		}
		
		// Handle software information
		if software, ok := svcMap["software"].(map[string]interface{}); ok {
			if vendor, ok := software["vendor"].(string); ok {
				svcData.Vendor = vendor
			}
			if product, ok := software["product"].(string); ok {
				svcData.Product = product
			}
			if version, ok := software["version"].(string); ok {
				svcData.Version = version
			}
		}
		
		// Handle vulnerabilities
		if vulns, ok := svcMap["vulnerabilities"]; ok {
			svcData.VulnIDs = parseVulnerabilities(vulns)
		}
		
		services[key] = svcData
	}
	
	return services, nil
}

// getIntFromInterface safely converts interface{} to int
func getIntFromInterface(val interface{}) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// parseVulnerabilities converts vulnerability data to string slice
func parseVulnerabilities(vulns interface{}) model.VulnIDs {
	var result model.VulnIDs
	
	switch v := vulns.(type) {
	case []interface{}:
		for _, vuln := range v {
			if str, ok := vuln.(string); ok {
				result = append(result, str)
			}
		}
	case []string:
		result = v
	case string:
		result = append(result, v)
	}
	
	return result.Canonicalize()
}

// ParseIPFromFilename extracts IP address from filename
func ParseIPFromFilename(filename string) (string, error) {
	if !strings.HasPrefix(filename, "host_") || !strings.HasSuffix(filename, ".json") {
		return "", fmt.Errorf("invalid filename format")
	}
	
	// Remove prefix and suffix
	inner := filename[5 : len(filename)-5]
	
	// Find the last underscore to separate IP from timestamp
	lastUnderscore := strings.LastIndex(inner, "_")
	if lastUnderscore == -1 {
		return "", fmt.Errorf("invalid filename format")
	}
	
	ip := inner[:lastUnderscore]
	if ip == "" {
		return "", fmt.Errorf("empty IP in filename")
	}
	
	return ip, nil
}

// ParseTimestampFromFilename extracts timestamp from filename
func ParseTimestampFromFilename(filename string) (string, error) {
	if !strings.HasPrefix(filename, "host_") || !strings.HasSuffix(filename, ".json") {
		return "", fmt.Errorf("invalid filename format")
	}
	
	// Remove prefix and suffix
	inner := filename[5 : len(filename)-5]
	
	// Find the last underscore to separate IP from timestamp
	lastUnderscore := strings.LastIndex(inner, "_")
	if lastUnderscore == -1 {
		return "", fmt.Errorf("invalid filename format")
	}
	
	timestamp := inner[lastUnderscore+1:]
	if timestamp == "" {
		return "", fmt.Errorf("empty timestamp in filename")
	}
	
	// Replace - with : to convert back to ISO format, but only for time parts
	// Format: 2025-09-10T03-00-00Z -> 2025-09-10T03:00:00Z
	parts := strings.Split(timestamp, "T")
	if len(parts) == 2 {
		datePart := parts[0]
		timePart := strings.ReplaceAll(parts[1], "-", ":")
		timestamp = datePart + "T" + timePart
	}
	
	return timestamp, nil
}
