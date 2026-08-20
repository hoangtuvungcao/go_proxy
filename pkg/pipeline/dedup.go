package pipeline

import (
	"hash/fnv"
	"sync"
	"time"
)

// ShardedDeduplicator loại bỏ trùng lặp IP với độ tranh chấp khóa (contention) cực thấp
// thông qua kiến trúc 64 shard độc lập.
type ShardedDeduplicator struct {
	shards [64]*dedupShard
	window time.Duration
}

type dedupShard struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

// NewShardedDeduplicator khởi tạo bộ lọc trùng lặp với cửa sổ thời gian cho trước
func NewShardedDeduplicator(window time.Duration) *ShardedDeduplicator {
	if window <= 0 {
		window = 10 * time.Minute
	}
	d := &ShardedDeduplicator{
		window: window,
	}
	for i := 0; i < 64; i++ {
		d.shards[i] = &dedupShard{
			entries: make(map[string]time.Time, 4096),
		}
	}

	// Dọn dẹp các entry cũ định kỳ trong nền
	go d.cleanupLoop()

	return d
}

// CheckAndSet trả về true nếu key CHƯA thấy trong cửa sổ thời gian (mới), false nếu trùng lặp.
// Đây là thao tác atomic check-and-set an toàn cho đa goroutine.
func (d *ShardedDeduplicator) CheckAndSet(key string) bool {
	h := fnv32(key)
	shard := d.shards[h%64]

	now := time.Now()
	shard.mu.Lock()
	defer shard.mu.Unlock()

	lastSeen, exists := shard.entries[key]
	if exists && now.Sub(lastSeen) < d.window {
		return false // Đã thấy trong cửa sổ thời gian → bỏ qua
	}

	shard.entries[key] = now
	return true
}

func (d *ShardedDeduplicator) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for i := 0; i < 64; i++ {
			shard := d.shards[i]
			shard.mu.Lock()
			for k, seen := range shard.entries {
				if now.Sub(seen) >= d.window {
					delete(shard.entries, k)
				}
			}
			shard.mu.Unlock()
		}
	}
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
