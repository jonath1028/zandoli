APP       := zandoli
CMD_PATH  := ./cmd/$(APP)
BIN       := ./build/$(APP)

.PHONY: build run clean test verify install demo lint fmt validate help

build:
	@echo "[*] Building $(APP)..."
	@go build -o $(BIN) $(CMD_PATH)
	@echo "    Binary: $(BIN) ($$(du -h $(BIN) | cut -f1))"

run: build
	@echo "[*] Running $(APP)..."
	$(BIN) --config=config.yaml

clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -rf ./build
	@echo "    Done."

test:
	@echo "[*] Running tests..."
	@go test ./... -count=1
	@echo "    All tests passed."

verify:
	@echo "[*] Running full verification (vet + test + build)..."
	@go vet ./...
	@go test ./... -count=1
	@go build ./...
	@echo "    Verification passed."

install: build
	@echo "[*] Installing $(APP)..."
	@sudo cp $(BIN) /usr/local/bin/$(APP)
	@sudo chmod 755 /usr/local/bin/$(APP)
	@sudo mkdir -p /etc/zandoli
	@sudo cp -n config.yaml /etc/zandoli/config.yaml 2>/dev/null || true
	@echo "    Installed to /usr/local/bin/$(APP)"
	@echo "    Config at /etc/zandoli/config.yaml"

validate: build
	@echo "[*] Running Wireshark PCAP validation..."
	@ZANDOLI=$(BIN) bash testdata/wireshark/validate.sh

demo: build
	@echo "[*] Running demo progress bars..."
	@$(BIN) --demo

lint:
	@echo "[*] Running linter..."
	@go vet ./...
	@echo "    go vet passed."

fmt:
	@echo "[*] Formatting code..."
	@go fmt ./...

help:
	@echo "Zandoli Makefile targets:"
	@echo "  build      Build the binary to build/zandoli"
	@echo "  run        Build and run with default config"
	@echo "  test       Run all tests"
	@echo "  verify     Run vet + tests + build (CI-ready)"
	@echo "  validate   Run Wireshark PCAP validation suite"
	@echo "  install    Install binary + config (requires sudo)"
	@echo "  clean      Remove build artifacts"
	@echo "  lint       Run go vet"
	@echo "  fmt        Format all Go code"
	@echo "  demo       Run progress bar demo"
	@echo "  help       Show this help"
