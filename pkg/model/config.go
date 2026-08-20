package model

import "time"

// Config contains all runtime configuration parameters
type Config struct {
	Engine   EngineConfig   `yaml:"engine" json:"engine"`
	Protocol ProtocolConfig `yaml:"protocol" json:"protocol"`
	Judge    JudgeConfig    `yaml:"judge" json:"judge"`
	Target   TargetConfig   `yaml:"target" json:"target"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	Server   ServerConfig   `yaml:"server" json:"server"`
	GeoIP    GeoIPConfig    `yaml:"geoip" json:"geoip"`
}

// EngineConfig configures concurrency, timeouts, and rate limits
type EngineConfig struct {
	Workers          int           `yaml:"workers" json:"workers"`                     // Goroutine pool size (e.g. 5000)
	ConnectTimeout   time.Duration `yaml:"connect_timeout" json:"connect_timeout"`     // TCP dial timeout (e.g. 1.5s)
	ReadWriteTimeout time.Duration `yaml:"read_write_timeout" json:"read_write_timeout"` // Protocol read/write timeout (e.g. 3s)
	MaxQueueSize     int           `yaml:"max_queue_size" json:"max_queue_size"`       // Backpressure queue limit
	RateLimit        int           `yaml:"rate_limit" json:"rate_limit"`               // Max checks per second (0 = unlimited)
	MaxRetries       int           `yaml:"max_retries" json:"max_retries"`             // Retries before marking dead
	AutoPort         int           `yaml:"auto_port" json:"auto_port"`                 // Default port if input is only IP
}

// ProtocolConfig configures protocol probing behavior
type ProtocolConfig struct {
	Protocols   []Protocol `yaml:"protocols" json:"protocols"`       // http, https, socks4, socks5
	AutoDetect  bool       `yaml:"auto_detect" json:"auto_detect"`   // Try all protocols if not specified
	FastFailTCP bool       `yaml:"fast_fail_tcp" json:"fast_fail_tcp"` // Fast raw TCP connect check first
}

// JudgeConfig holds judge server endpoints and settings
type JudgeConfig struct {
	Judges         []string      `yaml:"judges" json:"judges"`                   // External judge URLs
	CustomJudgeURL string        `yaml:"custom_judge_url" json:"custom_judge_url"` // User's private VPS judge
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`                 // Judge request timeout
	ExpectBody     string        `yaml:"expect_body" json:"expect_body"`         // Optional expected string
}

// TargetConfig holds real-world target website validation
type TargetConfig struct {
	Enabled        bool          `yaml:"enabled" json:"enabled"`
	URL            string        `yaml:"url" json:"url"`                         // e.g. https://www.google.com or https://cloudflare.com
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	ExpectedStatus int           `yaml:"expected_status" json:"expected_status"` // 200
	MatchRegex     string        `yaml:"match_regex" json:"match_regex"`
}

// StorageConfig configures file outputs and database
type StorageConfig struct {
	OutputDir     string `yaml:"output_dir" json:"output_dir"`         // Directory for output files
	SaveSQLite    bool   `yaml:"save_sqlite" json:"save_sqlite"`       // Enable SQLite persistence
	DBPath        string `yaml:"db_path" json:"db_path"`               // Path to SQLite db
	SplitByCountry bool  `yaml:"split_by_country" json:"split_by_country"` // Output country-specific files
	SplitByType   bool   `yaml:"split_by_type" json:"split_by_type"`   // Output protocol-specific files
	SaveJSON      bool   `yaml:"save_json" json:"save_json"`           // Output json lines
	SaveCSV       bool   `yaml:"save_csv" json:"save_csv"`             // Output csv
}

// ServerConfig configures REST API and Web Dashboard
type ServerConfig struct {
	EnableAPI bool   `yaml:"enable_api" json:"enable_api"`
	APIAddr   string `yaml:"api_addr" json:"api_addr"` // e.g. ":8080"
	AuthToken string `yaml:"auth_token" json:"auth_token"` // Optional API token
}

// GeoIPConfig configures GeoIP resolution
type GeoIPConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	MMDBPath  string `yaml:"mmdb_path" json:"mmdb_path"` // Optional MaxMind GeoLite2-City.mmdb
	OnlineAPI bool   `yaml:"online_api" json:"online_api"` // Fallback to online lightweight API
}

// DefaultConfig returns optimal default configurations
func DefaultConfig() *Config {
	return &Config{
		Engine: EngineConfig{
			Workers:          2000,
			ConnectTimeout:   1500 * time.Millisecond,
			ReadWriteTimeout: 3000 * time.Millisecond,
			MaxQueueSize:     50000,
			RateLimit:        0,
			MaxRetries:       1,
			AutoPort:         8080,
		},
		Protocol: ProtocolConfig{
			Protocols:   []Protocol{ProtoHTTP, ProtoHTTPS, ProtoSOCKS5, ProtoSOCKS4},
			AutoDetect:  true,
			FastFailTCP: true,
		},
		Judge: JudgeConfig{
			Judges: []string{
				"https://api.ipify.org?format=json",
				"http://httpbin.org/ip",
				"https://ifconfig.me/ip",
				"https://api.myip.com",
			},
			Timeout: 3000 * time.Millisecond,
		},
		Target: TargetConfig{
			Enabled:        false,
			URL:            "https://www.google.com",
			Timeout:        3000 * time.Millisecond,
			ExpectedStatus: 200,
		},
		Storage: StorageConfig{
			OutputDir:      "output",
			SaveSQLite:     true,
			DBPath:         "proxies.db",
			SplitByCountry: true,
			SplitByType:    true,
			SaveJSON:       true,
			SaveCSV:        false,
		},
		Server: ServerConfig{
			EnableAPI: true,
			APIAddr:   ":8080",
		},
		GeoIP: GeoIPConfig{
			Enabled:   true,
			OnlineAPI: true,
		},
	}
}
