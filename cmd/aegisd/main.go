package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"aegiscore/pkg/daemon"
)

func main() {
	defaultPort := 8080
	if envPort := os.Getenv("PORT"); envPort != "" {
		if parsedPort, err := strconv.Atoi(envPort); err == nil {
			defaultPort = parsedPort
		}
	}

	port := flag.Int("port", defaultPort, "Secure Daemon listening API port")
	dbPath := flag.String("db", "audit_logs.jsonl", "Persistent audit ledger storage path")
	flag.Parse()

	log.Printf("[AEGIS-SECURE-DAEMON] Starting AegisCore Secure Orchestrator Daemon...")
	log.Printf("[AEGIS-SECURE-DAEMON] Loading transaction database at: %s", *dbPath)

	srv, err := daemon.NewDaemonServer(*dbPath)
	if err != nil {
		log.Fatalf("[AEGIS-FATAL] Daemon failed to initialize: %v", err)
	}

	handler := srv.SetupRoutes()
	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	
	log.Printf("[AEGIS-SECURE-DAEMON] Engine successfully running on %s", addr)
	log.Printf("[AEGIS-SECURE-DAEMON] Listening for secure process executions...")

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("[AEGIS-FATAL] Server socket crashed: %v", err)
	}
}
