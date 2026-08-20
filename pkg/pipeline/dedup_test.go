package pipeline

import (
	"testing"
	"time"
)

func TestShardedDeduplicator(t *testing.T) {
	dedup := NewShardedDeduplicator(1 * time.Second)

	// First time seen -> true
	if !dedup.CheckAndSet("1.1.1.1:8080:http") {
		t.Errorf("Expected first check to return true")
	}

	// Immediate duplicate -> false
	if dedup.CheckAndSet("1.1.1.1:8080:http") {
		t.Errorf("Expected duplicate check to return false")
	}

	// Different IP -> true
	if !dedup.CheckAndSet("2.2.2.2:8080:http") {
		t.Errorf("Expected distinct key to return true")
	}
}
