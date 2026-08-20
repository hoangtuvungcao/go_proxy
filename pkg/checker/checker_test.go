package checker

import (
	"testing"

	"goproxy/pkg/model"
)

func TestCalculateScore(t *testing.T) {
	// Elite fast proxy
	p1 := &model.Proxy{
		LatencyMs: 120,
		Anonymity: model.AnonElite,
		SSL:       true,
	}
	score1 := CalculateScore(p1)
	if score1 < 90 {
		t.Errorf("Expected high score for fast elite proxy, got %d", score1)
	}

	// Slow transparent proxy
	p2 := &model.Proxy{
		LatencyMs:     3500,
		Anonymity:     model.AnonTransparent,
		FailedChecks:  5,
		SuccessChecks: 5,
	}
	score2 := CalculateScore(p2)
	if score2 > 40 {
		t.Errorf("Expected low score for slow transparent proxy, got %d", score2)
	}
}
