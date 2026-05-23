package db

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditRecord represents a persistent security event entry
type AuditRecord struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SandboxID string    `json:"sandbox_id"`
	Type      string    `json:"type"`      // "SYSCALL", "ALERT", "SYSTEM"
	Level     string    `json:"level"`     // "INFO", "WARNING", "CRITICAL"
	Category  string    `json:"category"`  // "KERNEL", "DAEMON", "FILESYSTEM", etc.
	Action    string    `json:"action"`    // "openat", "connect", "PROCESS_START", etc.
	Message   string    `json:"message"`
}

// AuditDB represents our threat log transaction ledger
type AuditDB struct {
	filePath string
	records  []*AuditRecord
	counter  int64
	mutex    sync.RWMutex
}

// OpenAuditDB opens or constructs a persistent audit log file
func OpenAuditDB(filePath string) (*AuditDB, error) {
	db := &AuditDB{
		filePath: filePath,
		records:  make([]*AuditRecord, 0),
		counter:  0,
	}

	// Read existing records if the file exists
	if _, err := os.Stat(filePath); err == nil {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit store: %w", err)
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		for decoder.More() {
			var record AuditRecord
			if err := decoder.Decode(&record); err == nil {
				db.records = append(db.records, &record)
				if record.ID > db.counter {
					db.counter = record.ID
				}
			}
		}
	}

	return db, nil
}

// WriteRecord inserts a new security audit record into persistent storage
func (db *AuditDB) WriteRecord(sandboxID, recordType, level, category, action, message string) (*AuditRecord, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.counter++
	record := &AuditRecord{
		ID:        db.counter,
		Timestamp: time.Now(),
		SandboxID: sandboxID,
		Type:      recordType,
		Level:     level,
		Category:  category,
		Action:    action,
		Message:   message,
	}

	db.records = append(db.records, record)

	// Append transaction to local file
	file, err := os.OpenFile(db.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit store for append: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		return nil, fmt.Errorf("failed to encode transaction: %w", err)
	}

	return record, nil
}

// QueryRecords retrieves records for a specific sandbox, filtered by level
func (db *AuditDB) QueryRecords(sandboxID string, minLevel string) []*AuditRecord {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	results := make([]*AuditRecord, 0)
	for _, rec := range db.records {
		if sandboxID != "" && rec.SandboxID != sandboxID {
			continue
		}

		if minLevel != "" {
			if minLevel == "CRITICAL" && rec.Level != "CRITICAL" {
				continue
			}
			if minLevel == "WARNING" && rec.Level != "CRITICAL" && rec.Level != "WARNING" {
				continue
			}
		}

		results = append(results, rec)
	}

	return results
}

// Clear removes all audit trails (for administrative resets)
func (db *AuditDB) Clear() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.records = make([]*AuditRecord, 0)
	db.counter = 0

	_ = os.Remove(db.filePath)
	return nil
}
