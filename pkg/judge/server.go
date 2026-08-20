package judge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// StartJudgeServer runs an ultra-fast local HTTP judge server
func StartJudgeServer(addr string) error {
	mux := http.NewServeMux()

	// 1. IP endpoint
	mux.HandleFunc("/ip", func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, ip)
	})

	// 2. JSON endpoint (httpbin style)
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"origin":  ip,
			"headers": r.Header,
			"time":    time.Now().Unix(),
		})
	})

	// 3. AZENV.php compatibility endpoint
	mux.HandleFunc("/azenv.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		ip := getClientIP(r)
		_, _ = fmt.Fprintf(w, "REMOTE_ADDR = %s\n", ip)
		for k, v := range r.Header {
			normKey := strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
			_, _ = fmt.Fprintf(w, "HTTP_%s = %s\n", normKey, strings.Join(v, ", "))
		}
	})

	// Root fallback
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"origin": ip,
			"status": "ok",
		})
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return server.ListenAndServe()
}

func getClientIP(r *http.Request) string {
	// RemoteAddr has ip:port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
