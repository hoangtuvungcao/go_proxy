package judge

import (
	"net/http"
	"testing"

	"goproxy/pkg/model"
)

func TestEvaluateAnonymity(t *testing.T) {
	eval := NewEvaluator(nil, "")
	eval.myIP = "203.0.113.50" // Mock real client IP

	// 1. Transparent: headers contain client IP
	headersTrans := http.Header{
		"X-Forwarded-For": []string{"203.0.113.50, 1.1.1.1"},
	}
	if anon := eval.EvaluateAnonymity(headersTrans, []byte("")); anon != model.AnonTransparent {
		t.Errorf("Expected Transparent, got %s", anon)
	}

	// 2. Anonymous: hides IP but sends Via header
	headersAnon := http.Header{
		"Via": []string{"1.1 squid-proxy"},
	}
	if anon := eval.EvaluateAnonymity(headersAnon, []byte("")); anon != model.AnonAnonymous {
		t.Errorf("Expected Anonymous, got %s", anon)
	}

	// 3. Elite: clean headers
	headersElite := http.Header{
		"User-Agent": []string{"Mozilla/5.0"},
	}
	if anon := eval.EvaluateAnonymity(headersElite, []byte("{\"origin\": \"1.1.1.1\"}")); anon != model.AnonElite {
		t.Errorf("Expected Elite, got %s", anon)
	}
}
