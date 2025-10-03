package http

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/hostdiff/internal/db"
	"github.com/example/hostdiff/internal/diff"
	"github.com/example/hostdiff/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server represents the HTTP server
type Server struct {
	db       *db.DB
	tmpl     *template.Template
	router   *chi.Mux
}

// New initializes HTTP server with database connection
func New(database *db.DB) (*Server, error) {
	// Load templates
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	s := &Server{
		db:   database,
		tmpl: tmpl,
	}

	s.setupRoutes()
	return s, nil
}

// setupRoutes defines all API endpoints and middleware
func (s *Server) setupRoutes() {
	r := chi.NewRouter()
	
	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	
	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))
	
	// Pages
	r.Get("/", s.handleIndex)
	r.Get("/hosts/{ip}", s.handleHost)
	r.Get("/diff", s.handleDiff)
	
	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Post("/upload", s.handleUpload)
		r.Get("/hosts", s.handleGetHosts)
		r.Get("/hosts/{ip}/snapshots", s.handleGetSnapshots)
		r.Get("/snapshots/{id}", s.handleGetSnapshot)
		r.Post("/diff", s.handleAPIDiff)
	})
	
	// Health check
	r.Get("/healthz", s.handleHealth)
	
	s.router = r
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// handleIndex shows upload form and host list
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Get hosts data from database
	hosts, err := s.getHostSummaries()
	if err != nil {
		s.renderError(w, "Failed to load hosts", http.StatusInternalServerError)
		return
	}

	// Build hosts HTML
	hostsTable := ""
	if len(hosts) > 0 {
		for _, h := range hosts {
			hostsTable += fmt.Sprintf(`
				<tr>
					<td>%s</td>
					<td>%d</td>
					<td><a href="/hosts/%s" class="btn">View Snapshots</a></td>
				</tr>`, h.IP, h.SnapshotCount, h.IP)
		}
	} else {
		hostsTable = `<tr><td colspan="3" class="no-data">No hosts found. Upload a snapshot to get started.</td></tr>`
	}

	// Simple HTML response for now - could use templates but this is easier
	w.Header().Set("Content-Type", "text/html")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Host Diff Tool</title>
    <link rel="stylesheet" href="/static/styles.css">
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body>
    <header>
        <nav>
            <h1><a href="/">Host Diff Tool</a></h1>
        </nav>
    </header>
    
    <main>
        <div class="container">
            <h2>Upload Host Snapshot</h2>
            <form action="/api/upload" method="post" enctype="multipart/form-data" class="upload-form">
                <div class="form-group">
                    <label for="file">Select JSON file:</label>
                    <input type="file" id="file" name="file" accept=".json" required>
                </div>
                <button type="submit">Upload</button>
            </form>
            
            <div id="upload-result" class="alert" style="display: none;"></div>
            
            <h2>Hosts</h2>
            <table class="hosts-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Snapshots</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    %s
                </tbody>
            </table>
        </div>
    </main>
    
    <footer>
        <p>&copy; 2025 Host Diff Tool</p>
    </footer>
    
    <script>
    document.querySelector('.upload-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        const resultDiv = document.getElementById('upload-result');
        
        fetch('/api/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                resultDiv.className = 'alert alert-error';
                resultDiv.textContent = 'Error: ' + data.error;
            } else {
                resultDiv.className = 'alert alert-success';
                resultDiv.textContent = 'Upload successful!';
                setTimeout(() => window.location.reload(), 1000);
            }
            resultDiv.style.display = 'block';
        })
        .catch(error => {
            resultDiv.className = 'alert alert-error';
            resultDiv.textContent = 'Upload failed: ' + error.message;
            resultDiv.style.display = 'block';
        });
    });
    </script>
</body>
</html>
`, hostsTable)
	w.Write([]byte(html))
}

// handleHost shows snapshots for a specific host
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		s.renderError(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	snapshots, err := s.getSnapshotsForHost(ip)
	if err != nil {
		s.renderError(w, "Failed to load snapshots", http.StatusInternalServerError)
		return
	}

	// Build snapshots HTML
	snapshotsHTML := ""
	if len(snapshots) > 0 {
		snapshotsHTML = `
		<h3>Snapshots</h3>
		<table class="snapshots-table">
			<thead>
				<tr>
					<th>ID</th>
					<th>Observed At</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>`
		
		for _, snapshot := range snapshots {
			snapshotsHTML += fmt.Sprintf(`
				<tr>
					<td>%d</td>
					<td>%s</td>
					<td><a href="/api/snapshots/%d" class="btn btn-small" target="_blank">View JSON</a></td>
				</tr>`, snapshot.ID, snapshot.ObservedAt.Format("2006-01-02 15:04:05 UTC"), snapshot.ID)
		}
		
		snapshotsHTML += `
			</tbody>
		</table>
		
		<h3>Compare Snapshots</h3>
		<form action="/diff" method="get" class="compare-form">
			<div class="form-group">
				<label for="left">Left Snapshot:</label>
				<select id="left" name="left" required>
					<option value="">Select left snapshot</option>`
		
		for _, snapshot := range snapshots {
			snapshotsHTML += fmt.Sprintf(`<option value="%d">%s (ID: %d)</option>`, 
				snapshot.ID, snapshot.ObservedAt.Format("2006-01-02 15:04:05 UTC"), snapshot.ID)
		}
		
		snapshotsHTML += `
				</select>
			</div>
			
			<div class="form-group">
				<label for="right">Right Snapshot:</label>
				<select id="right" name="right" required>
					<option value="">Select right snapshot</option>`
		
		for _, snapshot := range snapshots {
			snapshotsHTML += fmt.Sprintf(`<option value="%d">%s (ID: %d)</option>`, 
				snapshot.ID, snapshot.ObservedAt.Format("2006-01-02 15:04:05 UTC"), snapshot.ID)
		}
		
		snapshotsHTML += `
				</select>
			</div>
			
			<button type="submit" class="btn">Compare</button>
		</form>`
	} else {
		snapshotsHTML = `<p class="no-data">No snapshots found for this host.</p>`
	}

	// Simple HTML response
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Host %s - Host Diff Tool</title>
    <link rel="stylesheet" href="/static/styles.css">
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body>
    <header>
        <nav>
            <h1><a href="/">Host Diff Tool</a></h1>
        </nav>
    </header>
    
    <main>
        <div class="container">
            <h2>Host: %s</h2>
            <p><a href="/" class="btn btn-secondary">← Back to Hosts</a></p>
            
            %s
        </div>
    </main>
    
    <footer>
        <p>&copy; 2025 Host Diff Tool</p>
    </footer>
</body>
</html>
`, ip, ip, snapshotsHTML)))
}

// handleDiff displays comparison between two snapshots
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	leftIDStr := r.URL.Query().Get("left")
	rightIDStr := r.URL.Query().Get("right")

	if leftIDStr == "" || rightIDStr == "" {
		s.renderError(w, "Missing left or right snapshot ID", http.StatusBadRequest)
		return
	}

	leftID, err := strconv.Atoi(leftIDStr)
	if err != nil {
		s.renderError(w, "Invalid left snapshot ID", http.StatusBadRequest)
		return
	}

	rightID, err := strconv.Atoi(rightIDStr)
	if err != nil {
		s.renderError(w, "Invalid right snapshot ID", http.StatusBadRequest)
		return
	}

	diffResult, err := s.computeDiff(leftID, rightID)
	if err != nil {
		s.renderError(w, "Failed to compute diff", http.StatusInternalServerError)
		return
	}

	// Build diff HTML
	diffHTML := fmt.Sprintf(`
	<div class="diff-summary">
		<h3>Summary</h3>
		<div class="summary-stats">
			<div class="stat">
				<span class="stat-label">Opened Ports:</span>
				<span class="stat-value">%d</span>
			</div>
			<div class="stat">
				<span class="stat-label">Closed Ports:</span>
				<span class="stat-value">%d</span>
			</div>
			<div class="stat">
				<span class="stat-label">Added Services:</span>
				<span class="stat-value">%d</span>
			</div>
			<div class="stat">
				<span class="stat-label">Removed Services:</span>
				<span class="stat-value">%d</span>
			</div>
			<div class="stat">
				<span class="stat-label">Service Changes:</span>
				<span class="stat-value">%d</span>
			</div>
		</div>
	</div>`, 
		len(diffResult.OpenedPorts), 
		len(diffResult.ClosedPorts), 
		len(diffResult.AddedServices), 
		len(diffResult.RemovedServices), 
		len(diffResult.ServiceChanges))

	// Add opened ports
	if len(diffResult.OpenedPorts) > 0 {
		diffHTML += `
		<div class="diff-section">
			<h3>Opened Ports</h3>
			<div class="port-list opened">`
		for _, port := range diffResult.OpenedPorts {
			diffHTML += fmt.Sprintf(`<span class="port">%d</span>`, port)
		}
		diffHTML += `</div></div>`
	}

	// Add closed ports
	if len(diffResult.ClosedPorts) > 0 {
		diffHTML += `
		<div class="diff-section">
			<h3>Closed Ports</h3>
			<div class="port-list closed">`
		for _, port := range diffResult.ClosedPorts {
			diffHTML += fmt.Sprintf(`<span class="port">%d</span>`, port)
		}
		diffHTML += `</div></div>`
	}

	// Add service changes
	if len(diffResult.ServiceChanges) > 0 {
		diffHTML += `
		<div class="diff-section">
			<h3>Service Changes</h3>
			<table class="changes-table">
				<thead>
					<tr>
						<th>Port/Protocol</th>
						<th>Changes</th>
						<th>Old Value</th>
						<th>New Value</th>
					</tr>
				</thead>
				<tbody>`
		
		for key, change := range diffResult.ServiceChanges {
			changes := ""
			if change.VendorChanged {
				changes += `<span class="change-tag vendor">Vendor</span>`
			}
			if change.ProductChanged {
				changes += `<span class="change-tag product">Product</span>`
			}
			if change.VersionChanged {
				changes += `<span class="change-tag version">Version</span>`
			}
			
			diffHTML += fmt.Sprintf(`
				<tr class="changed">
					<td>%s</td>
					<td>%s</td>
					<td>
						<div class="old-value">
							<div><strong>Vendor:</strong> %s</div>
							<div><strong>Product:</strong> %s</div>
							<div><strong>Version:</strong> %s</div>
						</div>
					</td>
					<td>
						<div class="new-value">
							<div><strong>Vendor:</strong> %s</div>
							<div><strong>Product:</strong> %s</div>
							<div><strong>Version:</strong> %s</div>
						</div>
					</td>
				</tr>`, 
				key, changes, 
				change.OldData.Vendor, change.OldData.Product, change.OldData.Version,
				change.NewData.Vendor, change.NewData.Product, change.NewData.Version)
		}
		
		diffHTML += `</tbody></table></div>`
	}

	diffHTML += `
	<div class="actions">
		<button id="download-json" class="btn">Download JSON</button>
	</div>`

	// Simple HTML response
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snapshot Comparison - Host Diff Tool</title>
    <link rel="stylesheet" href="/static/styles.css">
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body>
    <header>
        <nav>
            <h1><a href="/">Host Diff Tool</a></h1>
        </nav>
    </header>
    
    <main>
        <div class="container">
            <h2>Snapshot Comparison</h2>
            <p><a href="/" class="btn btn-secondary">← Back to Hosts</a></p>
            
            %s
        </div>
    </main>
    
    <footer>
        <p>&copy; 2025 Host Diff Tool</p>
    </footer>
    
    <script>
    document.getElementById('download-json').addEventListener('click', function() {
        const data = {
            left_id: %d,
            right_id: %d
        };
        
        fetch('/api/diff', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'diff_' + data.left_snapshot_id + '_' + data.right_snapshot_id + '.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        })
        .catch(error => {
            alert('Failed to download JSON: ' + error.message);
        });
    });
    </script>
</body>
</html>
`, diffHTML, leftID, rightID)))
}

// handleUpload processes JSON snapshot file uploads
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.renderJSONError(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file content
	content, err := io.ReadAll(file)
	if err != nil {
		s.renderJSONError(w, "Failed to read file", http.StatusBadRequest)
		return
	}

	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		s.renderJSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Extract IP and timestamp
	ip, observedAt, err := s.extractIPAndTimestamp(data, header.Filename)
	if err != nil {
		s.renderJSONError(w, fmt.Sprintf("Failed to extract IP/timestamp: %v", err), http.StatusUnprocessableEntity)
		return
	}

	// Parse services
	services, err := diff.ParseServicesFromJSON(data)
	if err != nil {
		s.renderJSONError(w, "Failed to parse services", http.StatusBadRequest)
		return
	}

	// Save to database
	if err := s.saveSnapshot(ip, observedAt, string(content), services); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			s.renderJSONError(w, "Snapshot for this host and timestamp already exists", http.StatusConflict)
			return
		}
		s.renderJSONError(w, "Failed to save snapshot", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Snapshot uploaded successfully"})
}

// handleGetHosts returns JSON list of all hosts
func (s *Server) handleGetHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.getHostSummaries()
	if err != nil {
		s.renderJSONError(w, "Failed to get hosts", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// handleGetSnapshots returns JSON list of snapshots for a host
func (s *Server) handleGetSnapshots(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		s.renderJSONError(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	snapshots, err := s.getSnapshotsForHost(ip)
	if err != nil {
		s.renderJSONError(w, "Failed to get snapshots", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}

// handleGetSnapshot returns JSON data for a specific snapshot
func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		s.renderJSONError(w, "Invalid snapshot ID", http.StatusBadRequest)
		return
	}

	snapshot, err := s.getSnapshotByID(id)
	if err != nil {
		if err == sql.ErrNoRows {
			s.renderJSONError(w, "Snapshot not found", http.StatusNotFound)
			return
		}
		s.renderJSONError(w, "Failed to get snapshot", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

// handleAPIDiff returns JSON diff between two snapshots
func (s *Server) handleAPIDiff(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeftID  int `json:"left_id"`
		RightID int `json:"right_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.renderJSONError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	diffResult, err := s.computeDiff(req.LeftID, req.RightID)
	if err != nil {
		s.renderJSONError(w, "Failed to compute diff", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diffResult)
}

// handleHealth returns basic health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// Helper methods

func (s *Server) extractIPAndTimestamp(jsonData map[string]interface{}, filename string) (string, time.Time, error) {
	var ip string
	var observedAt time.Time

	// Try to get IP from JSON
	if ipVal, ok := jsonData["ip"].(string); ok && ipVal != "" {
		ip = ipVal
	} else {
		// Parse from filename
		var err error
		ip, err = diff.ParseIPFromFilename(filename)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("could not extract IP from filename: %w", err)
		}
	}

	// Try to get timestamp from JSON (check both observed_at and timestamp)
	var timeVal string
	var found bool
	if timeVal, found = jsonData["observed_at"].(string); !found || timeVal == "" {
		timeVal, found = jsonData["timestamp"].(string)
	}
	
	if found && timeVal != "" {
		var err error
		observedAt, err = time.Parse(time.RFC3339, timeVal)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("invalid timestamp in JSON: %w", err)
		}
	} else {
		// Parse from filename
		timeStr, err := diff.ParseTimestampFromFilename(filename)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("could not extract timestamp from filename: %w", err)
		}
		observedAt, err = time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("invalid timestamp in filename: %w", err)
		}
	}

	return ip, observedAt, nil
}

func (s *Server) saveSnapshot(ip string, observedAt time.Time, rawJSON string, services map[model.ServiceKey]model.ServiceData) error {
	tx, err := s.db.GetDB().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Upsert host
	var hostID int
	err = tx.QueryRow("SELECT id FROM hosts WHERE ip = ?", ip).Scan(&hostID)
	if err == sql.ErrNoRows {
		result, err := tx.Exec("INSERT INTO hosts (ip) VALUES (?)", ip)
		if err != nil {
			return err
		}
		hostID64, err := result.LastInsertId()
		if err != nil {
			return err
		}
		hostID = int(hostID64)
	} else if err != nil {
		return err
	}

	// Insert snapshot
	result, err := tx.Exec("INSERT INTO snapshots (host_id, observed_at, raw_json) VALUES (?, ?, ?)",
		hostID, observedAt, rawJSON)
	if err != nil {
		return err
	}
	snapshotID64, err := result.LastInsertId()
	if err != nil {
		return err
	}
	snapshotID := int(snapshotID64)

	// Insert services
	for key, data := range services {
		_, err = tx.Exec(`INSERT INTO services (snapshot_id, port, protocol, service_name, product, vendor, version, vuln_ids) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			snapshotID, key.Port, key.Protocol, data.ServiceName, data.Product, data.Vendor, data.Version, data.VulnIDs)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Server) getHostSummaries() ([]model.HostSummary, error) {
	rows, err := s.db.GetDB().Query(`
		SELECT h.ip, COUNT(s.id) as snapshot_count
		FROM hosts h
		LEFT JOIN snapshots s ON h.id = s.host_id
		GROUP BY h.id, h.ip
		ORDER BY h.ip
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []model.HostSummary
	for rows.Next() {
		var host model.HostSummary
		err := rows.Scan(&host.IP, &host.SnapshotCount)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (s *Server) getSnapshotsForHost(ip string) ([]model.SnapshotSummary, error) {
	rows, err := s.db.GetDB().Query(`
		SELECT s.id, s.observed_at
		FROM snapshots s
		JOIN hosts h ON s.host_id = h.id
		WHERE h.ip = ?
		ORDER BY s.observed_at DESC
	`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []model.SnapshotSummary
	for rows.Next() {
		var snapshot model.SnapshotSummary
		err := rows.Scan(&snapshot.ID, &snapshot.ObservedAt)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

func (s *Server) getSnapshotByID(id int) (*model.Snapshot, error) {
	var snapshot model.Snapshot
	err := s.db.GetDB().QueryRow("SELECT id, host_id, observed_at, raw_json FROM snapshots WHERE id = ?", id).
		Scan(&snapshot.ID, &snapshot.HostID, &snapshot.ObservedAt, &snapshot.RawJSON)
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func (s *Server) computeDiff(leftID, rightID int) (*model.DiffResult, error) {
	// Get snapshots
	leftSnapshot, err := s.getSnapshotByID(leftID)
	if err != nil {
		return nil, err
	}
	rightSnapshot, err := s.getSnapshotByID(rightID)
	if err != nil {
		return nil, err
	}

	// Parse services from both snapshots
	var leftJSON, rightJSON map[string]interface{}
	if err := json.Unmarshal([]byte(leftSnapshot.RawJSON), &leftJSON); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(rightSnapshot.RawJSON), &rightJSON); err != nil {
		return nil, err
	}

	leftServices, err := diff.ParseServicesFromJSON(leftJSON)
	if err != nil {
		return nil, err
	}
	rightServices, err := diff.ParseServicesFromJSON(rightJSON)
	if err != nil {
		return nil, err
	}

	// Compute diff
	diffResult := diff.CompareSnapshots(leftServices, rightServices)
	diffResult.LeftSnapshotID = leftID
	diffResult.RightSnapshotID = rightID

	return &diffResult, nil
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		fmt.Printf("Template error: %v\n", err)
		http.Error(w, fmt.Sprintf("Template error: %v", err), http.StatusInternalServerError)
	}
}

func (s *Server) renderError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	data := map[string]interface{}{
		"Title":   "Error",
		"Message": message,
	}
	s.renderTemplate(w, "layout.tmpl", data)
}

func (s *Server) renderJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func loadTemplates() (*template.Template, error) {
	// Define templates inline to avoid file path issues
	tmpl := template.New("")
	
	// Layout template
	layoutTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}} - Host Diff Tool</title>
    <link rel="stylesheet" href="/static/styles.css">
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
</head>
<body>
    <header>
        <nav>
            <h1><a href="/">Host Diff Tool</a></h1>
        </nav>
    </header>
    
    <main>
        {{template "content" .}}
    </main>
    
    <footer>
        <p>&copy; 2025 Host Diff Tool</p>
    </footer>
</body>
</html>`
	
	// Index template
	indexTemplate := `{{define "content"}}
<div class="container">
    <h2>Upload Host Snapshot</h2>
    <form action="/api/upload" method="post" enctype="multipart/form-data" class="upload-form">
        <div class="form-group">
            <label for="file">Select JSON file:</label>
            <input type="file" id="file" name="file" accept=".json" required>
        </div>
        <button type="submit">Upload</button>
    </form>
    
    <div id="upload-result" class="alert" style="display: none;"></div>
    
    <h2>Hosts</h2>
    {{if .Hosts}}
    <table class="hosts-table">
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Snapshots</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {{range .Hosts}}
            <tr>
                <td>{{.IP}}</td>
                <td>{{.SnapshotCount}}</td>
                <td><a href="/hosts/{{.IP}}" class="btn">View Snapshots</a></td>
            </tr>
            {{end}}
        </tbody>
    </table>
    {{else}}
    <p class="no-data">No hosts found. Upload a snapshot to get started.</p>
    {{end}}
</div>

<script>
document.querySelector('.upload-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const resultDiv = document.getElementById('upload-result');
    
    fetch('/api/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultDiv.className = 'alert alert-error';
            resultDiv.textContent = 'Error: ' + data.error;
        } else {
            resultDiv.className = 'alert alert-success';
            resultDiv.textContent = 'Upload successful!';
            setTimeout(() => window.location.reload(), 1000);
        }
        resultDiv.style.display = 'block';
    })
    .catch(error => {
        resultDiv.className = 'alert alert-error';
        resultDiv.textContent = 'Upload failed: ' + error.message;
        resultDiv.style.display = 'block';
    });
});
</script>
{{end}}`
	
	// Host template
	hostTemplate := `{{define "content"}}
<div class="container">
    <h2>Host: {{.IP}}</h2>
    <p><a href="/" class="btn btn-secondary">← Back to Hosts</a></p>
    
    {{if .Snapshots}}
    <h3>Snapshots</h3>
    <table class="snapshots-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Observed At</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {{range .Snapshots}}
            <tr>
                <td>{{.ID}}</td>
                <td>{{.ObservedAt.Format "2006-01-02 15:04:05 UTC"}}</td>
                <td><a href="/api/snapshots/{{.ID}}" class="btn btn-small" target="_blank">View JSON</a></td>
            </tr>
            {{end}}
        </tbody>
    </table>
    
    <h3>Compare Snapshots</h3>
    <form action="/diff" method="get" class="compare-form">
        <div class="form-group">
            <label for="left">Left Snapshot:</label>
            <select id="left" name="left" required>
                <option value="">Select left snapshot</option>
                {{range .Snapshots}}
                <option value="{{.ID}}">{{.ObservedAt.Format "2006-01-02 15:04:05 UTC"}} (ID: {{.ID}})</option>
                {{end}}
            </select>
        </div>
        
        <div class="form-group">
            <label for="right">Right Snapshot:</label>
            <select id="right" name="right" required>
                <option value="">Select right snapshot</option>
                {{range .Snapshots}}
                <option value="{{.ID}}">{{.ObservedAt.Format "2006-01-02 15:04:05 UTC"}} (ID: {{.ID}})</option>
                {{end}}
            </select>
        </div>
        
        <button type="submit" class="btn">Compare</button>
    </form>
    {{else}}
    <p class="no-data">No snapshots found for this host.</p>
    {{end}}
</div>
{{end}}`
	
	// Diff template
	diffTemplate := `{{define "content"}}
<div class="container">
    <h2>Snapshot Comparison</h2>
    <p><a href="/" class="btn btn-secondary">← Back to Hosts</a></p>
    
    <div class="diff-summary">
        <h3>Summary</h3>
        <div class="summary-stats">
            <div class="stat">
                <span class="stat-label">Opened Ports:</span>
                <span class="stat-value">{{len .DiffResult.OpenedPorts}}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Closed Ports:</span>
                <span class="stat-value">{{len .DiffResult.ClosedPorts}}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Added Services:</span>
                <span class="stat-value">{{len .DiffResult.AddedServices}}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Removed Services:</span>
                <span class="stat-value">{{len .DiffResult.RemovedServices}}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Service Changes:</span>
                <span class="stat-value">{{len .DiffResult.ServiceChanges}}</span>
            </div>
        </div>
    </div>
    
    {{if .DiffResult.OpenedPorts}}
    <div class="diff-section">
        <h3>Opened Ports</h3>
        <div class="port-list opened">
            {{range .DiffResult.OpenedPorts}}
            <span class="port">{{.}}</span>
            {{end}}
        </div>
    </div>
    {{end}}
    
    {{if .DiffResult.ClosedPorts}}
    <div class="diff-section">
        <h3>Closed Ports</h3>
        <div class="port-list closed">
            {{range .DiffResult.ClosedPorts}}
            <span class="port">{{.}}</span>
            {{end}}
        </div>
    </div>
    {{end}}
    
    {{if .DiffResult.AddedServices}}
    <div class="diff-section">
        <h3>Added Services</h3>
        <table class="services-table">
            <thead>
                <tr>
                    <th>Port/Protocol</th>
                    <th>Service Name</th>
                    <th>Product</th>
                    <th>Vendor</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                </tr>
            </thead>
            <tbody>
                {{range $key, $service := .DiffResult.AddedServices}}
                <tr class="added">
                    <td>{{$key}}</td>
                    <td>{{$service.ServiceName}}</td>
                    <td>{{$service.Product}}</td>
                    <td>{{$service.Vendor}}</td>
                    <td>{{$service.Version}}</td>
                    <td>
                        {{range $service.VulnIDs}}
                        <span class="vuln">{{.}}</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
    
    {{if .DiffResult.RemovedServices}}
    <div class="diff-section">
        <h3>Removed Services</h3>
        <table class="services-table">
            <thead>
                <tr>
                    <th>Port/Protocol</th>
                    <th>Service Name</th>
                    <th>Product</th>
                    <th>Vendor</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                </tr>
            </thead>
            <tbody>
                {{range $key, $service := .DiffResult.RemovedServices}}
                <tr class="removed">
                    <td>{{$key}}</td>
                    <td>{{$service.ServiceName}}</td>
                    <td>{{$service.Product}}</td>
                    <td>{{$service.Vendor}}</td>
                    <td>{{$service.Version}}</td>
                    <td>
                        {{range $service.VulnIDs}}
                        <span class="vuln">{{.}}</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
    
    {{if .DiffResult.ServiceChanges}}
    <div class="diff-section">
        <h3>Service Changes</h3>
        <table class="changes-table">
            <thead>
                <tr>
                    <th>Port/Protocol</th>
                    <th>Changes</th>
                    <th>Old Value</th>
                    <th>New Value</th>
                    <th>Vulns Added</th>
                    <th>Vulns Removed</th>
                </tr>
            </thead>
            <tbody>
                {{range $key, $change := .DiffResult.ServiceChanges}}
                <tr class="changed">
                    <td>{{$key}}</td>
                    <td>
                        {{if $change.VendorChanged}}<span class="change-tag vendor">Vendor</span>{{end}}
                        {{if $change.ProductChanged}}<span class="change-tag product">Product</span>{{end}}
                        {{if $change.VersionChanged}}<span class="change-tag version">Version</span>{{end}}
                    </td>
                    <td>
                        <div class="old-value">
                            <div><strong>Vendor:</strong> {{$change.OldData.Vendor}}</div>
                            <div><strong>Product:</strong> {{$change.OldData.Product}}</div>
                            <div><strong>Version:</strong> {{$change.OldData.Version}}</div>
                        </div>
                    </td>
                    <td>
                        <div class="new-value">
                            <div><strong>Vendor:</strong> {{$change.NewData.Vendor}}</div>
                            <div><strong>Product:</strong> {{$change.NewData.Product}}</div>
                            <div><strong>Version:</strong> {{$change.NewData.Version}}</div>
                        </div>
                    </td>
                    <td>
                        {{range $change.VulnsAdded}}
                        <span class="vuln added">{{.}}</span>
                        {{end}}
                    </td>
                    <td>
                        {{range $change.VulnsRemoved}}
                        <span class="vuln removed">{{.}}</span>
                        {{end}}
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
    
    <div class="actions">
        <button id="download-json" class="btn">Download JSON</button>
    </div>
</div>

<script>
document.getElementById('download-json').addEventListener('click', function() {
    const data = {
        left_id: {{.LeftID}},
        right_id: {{.RightID}}
    };
    
    fetch('/api/diff', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'diff_' + data.left_snapshot_id + '_' + data.right_snapshot_id + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    })
    .catch(error => {
        alert('Failed to download JSON: ' + error.message);
    });
});
</script>
{{end}}`
	
	// Parse templates
	_, err := tmpl.New("layout.tmpl").Parse(layoutTemplate)
	if err != nil {
		return nil, err
	}
	
	_, err = tmpl.New("index.tmpl").Parse(indexTemplate)
	if err != nil {
		return nil, err
	}
	
	_, err = tmpl.New("host.tmpl").Parse(hostTemplate)
	if err != nil {
		return nil, err
	}
	
	_, err = tmpl.New("diff.tmpl").Parse(diffTemplate)
	if err != nil {
		return nil, err
	}
	
	return tmpl, nil
}
