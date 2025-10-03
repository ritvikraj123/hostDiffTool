# Host Diff Tool

A minimal web application for comparing host snapshots and tracking changes in services, ports, and vulnerabilities over time.

## Features

- **Upload host snapshots** in JSON format
- **Compare snapshots** for the same host to see changes
- **Track service changes** including ports, protocols, versions, and vulnerabilities
- **Persistent storage** using SQLite
- **RESTful API** for programmatic access
- **Modern web interface** with HTMX for interactivity

## Quick Start

### Local Development

```bash
# Clone and navigate to the project
git clone <your-repo-url>
cd censys_hostDiffTool

# Install dependencies
go mod download

# Run the application
go run ./cmd/server

# Open http://localhost:8080
# Upload JSON snapshots to test the diff functionality
```

### Docker (Recommended)

```bash
# Start the application
docker compose up --build

# Open http://localhost:8080
# Upload JSON snapshots to test the diff functionality
```

## Assumptions

- **Snapshot JSON structure**: `ip`, `observed_at` (ISO-8601), `services[]` with `port`, `protocol`, `service_name`, `software.vendor/product/version`, `vulnerabilities[]`
- **Protocol normalization**: Converted to upper-case ("TCP")
- **Vulnerabilities**: Compared by ID as string set
- **Filename parsing**: If `ip` or `observed_at` missing from JSON, parsed from filename format `host_<ip>_<timestamp>.json`

## Testing

### Unit Tests
```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test ./internal/diff
```

### Manual Testing
1. Upload snapshot A for a host
2. Upload snapshot B for the same host
3. Open host page → select two snapshots → view diff
4. Verify opened/closed ports, added/removed services, and service changes

## API Examples

### Upload a snapshot

```bash
curl -X POST -F "file=@host_192.168.1.1_2025-09-10T03-00-00Z.json" http://localhost:8080/api/upload
```

### List all hosts

```bash
curl http://localhost:8080/api/hosts
```

### Get snapshots for a host

```bash
curl http://localhost:8080/api/hosts/192.168.1.1/snapshots
```

### Compare two snapshots

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"left_id": 1, "right_id": 2}' \
  http://localhost:8080/api/diff
```

### Health check

```bash
curl http://localhost:8080/healthz
```

## JSON Input Format

The application accepts host snapshots in JSON format. Here's an example:

```json
{
  "ip": "192.168.1.1",
  "observed_at": "2025-09-10T03:00:00Z",
  "services": [
    {
      "port": 22,
      "protocol": "tcp",
      "service_name": "ssh",
      "software": {
        "vendor": "openssh",
        "product": "openssh",
        "version": "8.2p1"
      },
      "vulnerabilities": ["CVE-2023-99992"]
    },
    {
      "port": 80,
      "protocol": "tcp",
      "service_name": "http",
      "software": {
        "vendor": "nginx",
        "product": "nginx",
        "version": "1.18.0"
      },
      "vulnerabilities": []
    }
  ]
}
```

### Filename Parsing

If `ip` or `observed_at` are missing from the JSON, the application will attempt to parse them from the filename using the format:
`host_<ip>_<timestamp>.json`

Where timestamp is ISO-8601 format with colons replaced by dashes.

## Diff Output

The diff comparison provides:

- **Opened ports**: Ports present in the right snapshot but not the left
- **Closed ports**: Ports present in the left snapshot but not the right
- **Added services**: Services present only in the right snapshot
- **Removed services**: Services present only in the left snapshot
- **Service changes**: Changes to existing services including:
  - Vendor changes
  - Product changes
  - Version changes
  - Vulnerability additions/removals

## Development

### Project Structure

```
hostdiff/
├── cmd/server/           # Main application entry point
├── internal/
│   ├── db/              # Database models and migrations
│   ├── diff/            # Diff logic and tests
│   ├── http/            # HTTP handlers and templates
│   └── model/           # Data models
├── web/static/          # Static assets (CSS)
├── Dockerfile           # Multi-stage Docker build
├── docker-compose.yml   # Docker Compose configuration
└── Makefile            # Development commands
```

### Available Make Targets

- `make deps` - Download Go dependencies
- `make test` - Run tests
- `make build` - Build the application
- `make run` - Run locally
- `make clean` - Clean build artifacts
- `make docker-build` - Build Docker image
- `make docker-up` - Start with Docker Compose
- `make docker-down` - Stop Docker Compose

### Testing

The application includes comprehensive tests for the diff logic:

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test ./internal/diff
```

## Database Schema

The application uses SQLite with the following tables:

- `hosts` - Host information (IP addresses)
- `snapshots` - Host snapshots with timestamps
- `services` - Parsed service information from snapshots

## AI Techniques Used

Used AI assistants (e.g., Cursor/ChatGPT) for boilerplate generation and refactors; all logic reviewed and verified manually. No runtime AI component; optional "AI summaries" listed under Future Enhancements.

## Future Enhancements

- **Improve security & usability**: Add authentication and basic user management.
- **Enhance data handling**: Support larger databases (e.g., PostgreSQL) and add search/filtering for hosts and snapshots.
- **Better reporting**: Enable CSV export and simple summaries of snapshot differences.
- **UI improvements**: Add pagination and polish the web interface for easier navigation.
- **Extended insights**: integrate AI-powered change summaries.