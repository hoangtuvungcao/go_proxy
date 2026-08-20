package protocol

import (
	"net/http"
	"testing"
)

func TestValidateJudgeResponse(t *testing.T) {
	headers := make(http.Header)

	// Valid cases (Real proxy responses)
	validCases := [][]byte{
		[]byte(`{"origin": "14.225.207.61"}`),
		[]byte(`{"ip": "14.225.207.61"}`),
		[]byte(`{"origin": "14.225.207.61, 10.0.0.1"}`),
		[]byte(`{"query": "118.69.188.67"}`),
		[]byte("14.225.207.61\n"),
		[]byte("\"14.225.207.61\""),
		[]byte("REMOTE_ADDR = 14.225.207.61\nHTTP_USER_AGENT = Go\n"),
	}

	for i, body := range validCases {
		if err := validateJudgeResponse(headers, body); err != nil {
			t.Errorf("Valid case #%d failed: %v | Body: %s", i, err, string(body))
		}
	}

	// Invalid cases (Websites, Routers, Login portals, 404s, Captive portals)
	invalidCases := [][]byte{
		[]byte("<!DOCTYPE html><html><title>MikroTik RouterOS</title><body>Login here. origin ip</body></html>"),
		[]byte("<html><head><title>TP-Link Wireless Router</title></head><body>origin ip login</body></html>"),
		[]byte("<html><body><h1>404 Not Found</h1>nginx/1.18.0 origin</body></html>"),
		[]byte("<script>window.origin = 'http://localhost';</script>"),
		[]byte("Welcome to our website! Check your IP address here."),
		[]byte(""),
		[]byte("ok"),
		[]byte("{\"error\": \"not found\"}"),
		[]byte("{\"origin\": \"not-an-ip\"}"),
	}

	for i, body := range invalidCases {
		if err := validateJudgeResponse(headers, body); err == nil {
			t.Errorf("Invalid case #%d falsely PASSED | Body: %s", i, string(body))
		}
	}
}
