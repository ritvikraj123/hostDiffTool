# Makefile for hostdiff

# Default values
PORT ?= 8080
DATABASE_URL ?= file:./app.db

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=hostdiff
BINARY_UNIX=$(BINARY_NAME)_unix

# Build directory
BUILD_DIR=bin

.PHONY: all build clean test run deps docker-build docker-up docker-down help

# Default target
all: deps test build

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) ./...

# Build the application
build:
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/server

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f app.db

# Run the application locally
run:
	PORT=$(PORT) DATABASE_URL=$(DATABASE_URL) $(GOCMD) run ./cmd/server

# Docker build
docker-build:
	docker build -t hostdiff .

# Docker compose up
docker-up:
	docker-compose up -d

# Docker compose down
docker-down:
	docker-compose down

# Docker compose logs
docker-logs:
	docker-compose logs -f

# Docker compose restart
docker-restart:
	docker-compose restart

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Install deps, run tests, and build"
	@echo "  deps         - Download and tidy Go modules"
	@echo "  test         - Run tests"
	@echo "  build        - Build the application"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Run the application locally"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-up    - Start with docker-compose"
	@echo "  docker-down  - Stop docker-compose"
	@echo "  docker-logs  - Show docker-compose logs"
	@echo "  docker-restart - Restart docker-compose"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  PORT         - Port to run on (default: 8080)"
	@echo "  DATABASE_URL - Database URL (default: file:./app.db)"
