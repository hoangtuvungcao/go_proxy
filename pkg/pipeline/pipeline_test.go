package pipeline

import (
	"strings"
	"testing"

	"goproxy/pkg/model"
)

func TestParseLineToJob(t *testing.T) {
	tests := []struct {
		input        string
		defaultPort  int
		defaultProto model.Protocol
		expectedIP   string
		expectedPort int
		expectedProto model.Protocol
	}{
		{
			input:        "1.1.1.1",
			defaultPort:  8080,
			defaultProto: model.ProtoHTTP,
			expectedIP:   "1.1.1.1",
			expectedPort: 8080,
			expectedProto: model.ProtoHTTP,
		},
		{
			input:        "103.28.37.1:1080",
			defaultPort:  8080,
			defaultProto: model.ProtoSOCKS5,
			expectedIP:   "103.28.37.1",
			expectedPort: 1080,
			expectedProto: model.ProtoSOCKS5,
		},
		{
			input:        "socks5://192.168.1.100:9050",
			defaultPort:  8080,
			defaultProto: model.ProtoHTTP,
			expectedIP:   "192.168.1.100",
			expectedPort: 9050,
			expectedProto: model.ProtoSOCKS5,
		},
		{
			input:        "http://45.33.32.156:3128",
			defaultPort:  8080,
			defaultProto: model.ProtoUnknown,
			expectedIP:   "45.33.32.156",
			expectedPort: 3128,
			expectedProto: model.ProtoHTTP,
		},
	}

	for _, tt := range tests {
		job, err := parseLineToJob(tt.input, tt.defaultPort, tt.defaultProto)
		if err != nil {
			t.Fatalf("Unexpected error for %s: %v", tt.input, err)
		}
		if job.IP != tt.expectedIP {
			t.Errorf("Expected IP %s, got %s", tt.expectedIP, job.IP)
		}
		if job.Port != tt.expectedPort {
			t.Errorf("Expected Port %d, got %d", tt.expectedPort, job.Port)
		}
		if job.Protocol != tt.expectedProto {
			t.Errorf("Expected Protocol %s, got %s", tt.expectedProto, job.Protocol)
		}
	}
}

func TestPipelineIngestion(t *testing.T) {
	cfg := model.DefaultConfig()
	cfg.Engine.Workers = 10
	p := NewPipeline(cfg, nil, nil, true)
	p.Start(10)

	input := "1.1.1.1\n8.8.8.8:53\nsocks5://9.9.9.9:1080\n"
	err := p.IngestFromReader(strings.NewReader(input), 8080, model.ProtoHTTP)
	if err != nil {
		t.Fatalf("Ingestion failed: %v", err)
	}

	p.Stop()

	if p.Stats().TotalQueued != 3 {
		t.Errorf("Expected 3 queued items, got %d", p.Stats().TotalQueued)
	}
}
