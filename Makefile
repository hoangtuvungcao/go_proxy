.PHONY: all build test clean run

BINARY_NAME=goproxy

all: test build

build:
	@echo "[*] Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) main.go
	@echo "[+] Build completed: ./$(BINARY_NAME)"

test:
	@echo "[*] Running unit tests..."
	go test -v ./...

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f test_proxies.db

run: build
	./$(BINARY_NAME) check --help
