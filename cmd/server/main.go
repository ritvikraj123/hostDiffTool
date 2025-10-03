package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/example/hostdiff/internal/db"
	httphandler "github.com/example/hostdiff/internal/http"
)

func main() {
	// Get database DSN
	dsn := db.GetDSN()
	
	// Create database connection
	database, err := db.New(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := db.Migrate(database.GetDB()); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Create HTTP server
	server, err := httphandler.New(database)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}

	// Get port from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting server on %s", addr)
	log.Printf("Database: %s", dsn)
	
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
