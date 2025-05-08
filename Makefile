APP = zandoli

build:
	go build -o $(APP) ./cmd/

run:
	go run ./cmd/ $(ARGS)

test:
	go test ./...

fmt:
	go fmt ./...

lint:
	@echo "[LINT] Running gofmt..."
	@gofmt -l -s . | tee /dev/stderr | (! grep .) || (echo "[ERROR] Code not properly formatted. Run 'make fmt'" && exit 1)
	@echo "[LINT] Running go vet..."
	@go vet ./...
	@echo "[LINT] Running staticcheck..."
	@staticcheck ./...


check:
	@echo "[CHECK] Formatting code..."
	@make fmt

	@echo "[CHECK] Running linters..."
	@make lint

	@echo "[CHECK] Building project..."
	@make build

	@echo "[CHECK] Running tests..."
	@make test

