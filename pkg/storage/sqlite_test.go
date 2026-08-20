package storage

import (
	"os"
	"testing"
	"time"

	"goproxy/pkg/model"
)

func TestSQLiteStore(t *testing.T) {
	dbPath := "test_proxies.db"
	defer os.Remove(dbPath)

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLite store: %v", err)
	}
	defer store.Close()

	// Insert test proxy
	p := &model.Proxy{
		IP:          "1.2.3.4",
		Port:        8080,
		Protocol:    model.ProtoHTTP,
		Anonymity:   model.AnonElite,
		Country:     "Vietnam",
		CountryCode: "VN",
		City:        "Hanoi",
		LatencyMs:   120,
		Score:       95,
		IsAlive:     true,
		FirstSeen:   time.Now(),
		LastAlive:   time.Now(),
	}

	err = store.SaveOrUpdateProxy(p)
	if err != nil {
		t.Fatalf("Failed to save proxy: %v", err)
	}
	store.Flush()

	// Query proxy
	list, err := store.QueryProxies(ProxyFilter{
		CountryCode: "VN",
		OnlyAlive:   true,
	})
	if err != nil {
		t.Fatalf("Failed to query proxies: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("Expected 1 proxy, got %d", len(list))
	}
	if list[0].IP != "1.2.3.4" || list[0].Port != 8080 {
		t.Errorf("Unexpected proxy data: %+v", list[0])
	}

	// Random proxy
	randomP, err := store.GetRandomAliveProxy("http", "VN")
	if err != nil {
		t.Fatalf("Failed to get random proxy: %v", err)
	}
	if randomP.IP != "1.2.3.4" {
		t.Errorf("Expected IP 1.2.3.4, got %s", randomP.IP)
	}

	// Alive count
	count, err := store.TotalAliveCount()
	if err != nil {
		t.Fatalf("Failed to count alive: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected count 1, got %d", count)
	}
}
