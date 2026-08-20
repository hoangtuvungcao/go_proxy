package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"goproxy/pkg/model"
)

// SQLiteStore manages high-throughput persistent proxy storage with asynchronous batch transactions
type SQLiteStore struct {
	db          *sql.DB
	mu          sync.RWMutex
	batchChan   chan *model.Proxy
	closeChan   chan struct{}
	wg          sync.WaitGroup
	batchSize   int
	flushPeriod time.Duration

	// Read cache for hot paths
	cachedAliveCount      int
	cachedAliveCountTime  time.Time
	cacheAliveCountMu     sync.Mutex
}

// NewSQLiteStore opens SQLite database with WAL mode and background transaction batching
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		dbPath = "proxies.db"
	}

	// WAL mode with performance tuning: 256MB mmap, large cache, checkpoint at 4000 pages
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=10000&_synchronous=NORMAL&_cache_size=-128000&_temp_store=MEMORY&_mmap_size=268435456&_wal_autocheckpoint=4000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(time.Hour)

	store := &SQLiteStore{
		db:          db,
		batchChan:   make(chan *model.Proxy, 50000),
		closeChan:   make(chan struct{}),
		batchSize:   200,
		flushPeriod: 250 * time.Millisecond,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	// Launch background batch committer
	store.wg.Add(1)
	go store.batchCommitter()

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS proxies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		anonymity TEXT NOT NULL,
		country TEXT,
		country_code TEXT,
		city TEXT,
		asn TEXT,
		org TEXT,
		latency_ms INTEGER,
		ssl INTEGER DEFAULT 0,
		target_ok INTEGER DEFAULT 0,
		score INTEGER DEFAULT 0,
		uptime_percent REAL DEFAULT 100.0,
		success_checks INTEGER DEFAULT 1,
		failed_checks INTEGER DEFAULT 0,
		consecutive_fail INTEGER DEFAULT 0,
		judge_count INTEGER DEFAULT 1,
		speed_kbps REAL DEFAULT 0.0,
		last_alive DATETIME,
		last_checked DATETIME,
		first_seen DATETIME,
		is_alive INTEGER DEFAULT 1,
		UNIQUE(ip, port, protocol)
	);

	-- Add new columns to existing databases (idempotent)
	ALTER TABLE proxies ADD COLUMN judge_count INTEGER DEFAULT 1; 
	ALTER TABLE proxies ADD COLUMN speed_kbps REAL DEFAULT 0.0;

	CREATE INDEX IF NOT EXISTS idx_proxies_filter ON proxies (is_alive, protocol, country_code, score);
	CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies (is_alive, latency_ms);
	CREATE INDEX IF NOT EXISTS idx_proxies_ip_port ON proxies (ip, port);
	CREATE INDEX IF NOT EXISTS idx_proxies_score_lat ON proxies (score DESC, latency_ms ASC) WHERE is_alive = 1;
	`
	// Execute each statement separately since ALTER TABLE will fail if column exists
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS proxies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			anonymity TEXT NOT NULL,
			country TEXT,
			country_code TEXT,
			city TEXT,
			asn TEXT,
			org TEXT,
			latency_ms INTEGER,
			ssl INTEGER DEFAULT 0,
			target_ok INTEGER DEFAULT 0,
			score INTEGER DEFAULT 0,
			uptime_percent REAL DEFAULT 100.0,
			success_checks INTEGER DEFAULT 1,
			failed_checks INTEGER DEFAULT 0,
			consecutive_fail INTEGER DEFAULT 0,
			judge_count INTEGER DEFAULT 1,
			speed_kbps REAL DEFAULT 0.0,
			last_alive DATETIME,
			last_checked DATETIME,
			first_seen DATETIME,
			is_alive INTEGER DEFAULT 1,
			UNIQUE(ip, port, protocol)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_filter ON proxies (is_alive, protocol, country_code, score)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies (is_alive, latency_ms)`,
		`CREATE INDEX IF NOT EXISTS idx_proxies_ip_port ON proxies (ip, port)`,
	}
	migrateStmts := []string{
		`ALTER TABLE proxies ADD COLUMN judge_count INTEGER DEFAULT 1`,
		`ALTER TABLE proxies ADD COLUMN speed_kbps REAL DEFAULT 0.0`,
	}
	_ = query // Suppress unused warning
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("schema init: %w", err)
		}
	}
	// Migrations are idempotent (ignore errors — column already exists)
	for _, stmt := range migrateStmts {
		_, _ = s.db.Exec(stmt)
	}
	return nil
}

// SaveOrUpdateProxy queues a proxy for high-throughput batch transaction persistence
func (s *SQLiteStore) SaveOrUpdateProxy(p *model.Proxy) error {
	select {
	case s.batchChan <- p:
		return nil
	default:
		// Channel full, commit synchronously as fallback
		return s.commitSingleProxy(p)
	}
}

// batchCommitter batches multiple proxy upserts into single atomic SQLite transactions
func (s *SQLiteStore) batchCommitter() {
	defer s.wg.Done()

	buffer := make([]*model.Proxy, 0, s.batchSize)
	ticker := time.NewTicker(s.flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeChan:
			// Drain remaining items in queue
			for {
				select {
				case p := <-s.batchChan:
					buffer = append(buffer, p)
					if len(buffer) >= s.batchSize {
						s.flushBatch(buffer)
						buffer = buffer[:0]
					}
				default:
					if len(buffer) > 0 {
						s.flushBatch(buffer)
					}
					return
				}
			}

		case p := <-s.batchChan:
			buffer = append(buffer, p)
			if len(buffer) >= s.batchSize {
				s.flushBatch(buffer)
				buffer = buffer[:0]
			}

		case <-ticker.C:
			if len(buffer) > 0 {
				s.flushBatch(buffer)
				buffer = buffer[:0]
			}
		}
	}
}

// Flush immediately commits all currently buffered items in the batch channel
func (s *SQLiteStore) Flush() {
	var buffer []*model.Proxy
	for {
		select {
		case p := <-s.batchChan:
			buffer = append(buffer, p)
		default:
			if len(buffer) > 0 {
				s.flushBatch(buffer)
			}
			return
		}
	}
}

func (s *SQLiteStore) flushBatch(proxies []*model.Proxy) {
	if len(proxies) == 0 {
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		return
	}

	query := `
	INSERT INTO proxies (
		ip, port, protocol, anonymity, country, country_code, city, asn, org,
		latency_ms, ssl, target_ok, score, uptime_percent, success_checks, failed_checks,
		consecutive_fail, last_alive, last_checked, first_seen, is_alive
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip, port, protocol) DO UPDATE SET
		anonymity = excluded.anonymity,
		country = excluded.country,
		country_code = excluded.country_code,
		city = excluded.city,
		asn = excluded.asn,
		org = excluded.org,
		latency_ms = excluded.latency_ms,
		ssl = excluded.ssl,
		target_ok = excluded.target_ok,
		score = excluded.score,
		success_checks = proxies.success_checks + CASE WHEN excluded.is_alive = 1 THEN 1 ELSE 0 END,
		failed_checks = proxies.failed_checks + CASE WHEN excluded.is_alive = 0 THEN 1 ELSE 0 END,
		consecutive_fail = CASE WHEN excluded.is_alive = 1 THEN 0 ELSE proxies.consecutive_fail + 1 END,
		uptime_percent = ROUND((CAST(proxies.success_checks + CASE WHEN excluded.is_alive = 1 THEN 1 ELSE 0 END AS REAL) / 
			CAST(proxies.success_checks + proxies.failed_checks + 1 AS REAL)) * 100.0, 2),
		last_alive = CASE WHEN excluded.is_alive = 1 THEN excluded.last_alive ELSE proxies.last_alive END,
		last_checked = excluded.last_checked,
		is_alive = excluded.is_alive;
	`

	stmt, err := tx.Prepare(query)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()

	now := time.Now()
	for _, p := range proxies {
		if p.FirstSeen.IsZero() {
			p.FirstSeen = now
		}
		p.LastChecked = now
		if p.IsAlive {
			p.LastAlive = now
		}

		sslInt := 0
		if p.SSL {
			sslInt = 1
		}
		targetInt := 0
		if p.TargetOK {
			targetInt = 1
		}
		aliveInt := 0
		if p.IsAlive {
			aliveInt = 1
		}

		_, _ = stmt.Exec(
			p.IP, p.Port, string(p.Protocol), string(p.Anonymity), p.Country, p.CountryCode, p.City, p.ASN, p.Org,
			p.LatencyMs, sslInt, targetInt, p.Score, p.UptimePercent, p.SuccessChecks, p.FailedChecks,
			p.ConsecutiveFail, p.LastAlive, p.LastChecked, p.FirstSeen, aliveInt,
		)
	}

	_ = tx.Commit()
}

func (s *SQLiteStore) commitSingleProxy(p *model.Proxy) error {
	now := time.Now()
	if p.FirstSeen.IsZero() {
		p.FirstSeen = now
	}
	p.LastChecked = now
	if p.IsAlive {
		p.LastAlive = now
	}

	sslInt := 0
	if p.SSL {
		sslInt = 1
	}
	targetInt := 0
	if p.TargetOK {
		targetInt = 1
	}
	aliveInt := 0
	if p.IsAlive {
		aliveInt = 1
	}

	query := `
	INSERT INTO proxies (
		ip, port, protocol, anonymity, country, country_code, city, asn, org,
		latency_ms, ssl, target_ok, score, uptime_percent, success_checks, failed_checks,
		consecutive_fail, last_alive, last_checked, first_seen, is_alive
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip, port, protocol) DO UPDATE SET
		anonymity = excluded.anonymity,
		country = excluded.country,
		country_code = excluded.country_code,
		city = excluded.city,
		asn = excluded.asn,
		org = excluded.org,
		latency_ms = excluded.latency_ms,
		ssl = excluded.ssl,
		target_ok = excluded.target_ok,
		score = excluded.score,
		success_checks = proxies.success_checks + CASE WHEN excluded.is_alive = 1 THEN 1 ELSE 0 END,
		failed_checks = proxies.failed_checks + CASE WHEN excluded.is_alive = 0 THEN 1 ELSE 0 END,
		consecutive_fail = CASE WHEN excluded.is_alive = 1 THEN 0 ELSE proxies.consecutive_fail + 1 END,
		uptime_percent = ROUND((CAST(proxies.success_checks + CASE WHEN excluded.is_alive = 1 THEN 1 ELSE 0 END AS REAL) / 
			CAST(proxies.success_checks + proxies.failed_checks + 1 AS REAL)) * 100.0, 2),
		last_alive = CASE WHEN excluded.is_alive = 1 THEN excluded.last_alive ELSE proxies.last_alive END,
		last_checked = excluded.last_checked,
		is_alive = excluded.is_alive;
	`

	_, err := s.db.Exec(query,
		p.IP, p.Port, string(p.Protocol), string(p.Anonymity), p.Country, p.CountryCode, p.City, p.ASN, p.Org,
		p.LatencyMs, sslInt, targetInt, p.Score, p.UptimePercent, p.SuccessChecks, p.FailedChecks,
		p.ConsecutiveFail, p.LastAlive, p.LastChecked, p.FirstSeen, aliveInt,
	)
	return err
}

// ProxyFilter holds query filters
type ProxyFilter struct {
	Protocol    string
	CountryCode string
	Anonymity   string
	MinScore    int
	MaxLatency  int64
	OnlyAlive   bool
	Limit       int
	Offset      int
}

// QueryProxies retrieves proxies matching criteria
func (s *SQLiteStore) QueryProxies(filter ProxyFilter) ([]*model.Proxy, error) {
	query := "SELECT id, ip, port, protocol, anonymity, country, country_code, city, asn, org, latency_ms, ssl, target_ok, score, uptime_percent, success_checks, failed_checks, consecutive_fail, last_alive, last_checked, first_seen, is_alive FROM proxies WHERE 1=1"
	var args []interface{}

	if filter.OnlyAlive {
		query += " AND is_alive = 1"
	}
	if filter.Protocol != "" && filter.Protocol != "all" {
		query += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.CountryCode != "" && filter.CountryCode != "all" {
		query += " AND country_code = ?"
		args = append(args, strings.ToUpper(filter.CountryCode))
	}
	if filter.Anonymity != "" && filter.Anonymity != "all" {
		query += " AND anonymity = ?"
		args = append(args, filter.Anonymity)
	}
	if filter.MinScore > 0 {
		query += " AND score >= ?"
		args = append(args, filter.MinScore)
	}
	if filter.MaxLatency > 0 {
		query += " AND latency_ms <= ?"
		args = append(args, filter.MaxLatency)
	}

	query += " ORDER BY score DESC, latency_ms ASC"

	limit := 100
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	query += " LIMIT ?"
	args = append(args, limit)

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*model.Proxy
	for rows.Next() {
		var p model.Proxy
		var proto, anon string
		var ssl, target, alive int
		err := rows.Scan(
			&p.ID, &p.IP, &p.Port, &proto, &anon, &p.Country, &p.CountryCode, &p.City, &p.ASN, &p.Org,
			&p.LatencyMs, &ssl, &target, &p.Score, &p.UptimePercent, &p.SuccessChecks, &p.FailedChecks,
			&p.ConsecutiveFail, &p.LastAlive, &p.LastChecked, &p.FirstSeen, &alive,
		)
		if err != nil {
			continue
		}
		p.Protocol = model.Protocol(proto)
		p.Anonymity = model.Anonymity(anon)
		p.SSL = (ssl == 1)
		p.TargetOK = (target == 1)
		p.IsAlive = (alive == 1)
		p.Latency = time.Duration(p.LatencyMs) * time.Millisecond
		list = append(list, &p)
	}

	return list, nil
}

// GetRandomAliveProxy gets a high quality alive proxy from pool
func (s *SQLiteStore) GetRandomAliveProxy(proto string, country string) (*model.Proxy, error) {
	proxies, err := s.QueryProxies(ProxyFilter{
		Protocol:    proto,
		CountryCode: country,
		OnlyAlive:   true,
		MinScore:    50,
		Limit:       20,
	})
	if err != nil || len(proxies) == 0 {
		proxies, err = s.QueryProxies(ProxyFilter{OnlyAlive: true, Limit: 10})
		if err != nil || len(proxies) == 0 {
			return nil, fmt.Errorf("no alive proxies available")
		}
	}
	return proxies[time.Now().UnixNano()%int64(len(proxies))], nil
}

// TotalAliveCount returns current count of active proxies with a 500ms read cache
func (s *SQLiteStore) TotalAliveCount() (int, error) {
	s.cacheAliveCountMu.Lock()
	if time.Since(s.cachedAliveCountTime) < 500*time.Millisecond && s.cachedAliveCountTime != (time.Time{}) {
		count := s.cachedAliveCount
		s.cacheAliveCountMu.Unlock()
		return count, nil
	}
	s.cacheAliveCountMu.Unlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM proxies WHERE is_alive = 1").Scan(&count)
	if err == nil {
		s.cacheAliveCountMu.Lock()
		s.cachedAliveCount = count
		s.cachedAliveCountTime = time.Now()
		s.cacheAliveCountMu.Unlock()
	}
	return count, err
}

// PurgeDeadProxies removes permanently dead proxies to prevent DB bloating
func (s *SQLiteStore) PurgeDeadProxies(maxFail int, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	res, err := s.db.Exec("DELETE FROM proxies WHERE is_alive = 0 AND (consecutive_fail >= ? OR last_alive < ?)", maxFail, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountByProtocol returns alive proxy counts grouped by protocol
func (s *SQLiteStore) CountByProtocol() (map[string]int, error) {
	rows, err := s.db.Query("SELECT protocol, COUNT(*) FROM proxies WHERE is_alive = 1 GROUP BY protocol")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var proto string
		var count int
		if err := rows.Scan(&proto, &count); err == nil {
			result[proto] = count
		}
	}
	return result, nil
}

// CountByCountry returns top N countries by alive proxy count
func (s *SQLiteStore) CountByCountry(limit int) (map[string]int, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.Query(
		"SELECT country_code, COUNT(*) as cnt FROM proxies WHERE is_alive = 1 AND country_code != '' AND country_code != 'XX' GROUP BY country_code ORDER BY cnt DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var code string
		var count int
		if err := rows.Scan(&code, &count); err == nil {
			result[code] = count
		}
	}
	return result, nil
}

// CountByAnonymity returns alive proxy counts grouped by anonymity level
func (s *SQLiteStore) CountByAnonymity() (map[string]int, error) {
	rows, err := s.db.Query("SELECT anonymity, COUNT(*) FROM proxies WHERE is_alive = 1 GROUP BY anonymity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]int)
	for rows.Next() {
		var anon string
		var count int
		if err := rows.Scan(&anon, &count); err == nil {
			result[anon] = count
		}
	}
	return result, nil
}

// Close gracefully drains the batch committer and closes the database connection
func (s *SQLiteStore) Close() error {
	close(s.closeChan)
	s.wg.Wait()
	return s.db.Close()
}

