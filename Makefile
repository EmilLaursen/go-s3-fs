.PHONY: generate

# Do me!
generate:
	@go generate ./...
	@echo "[OK] Files added to embed box!"

security:
	@gosec ./...
	@echo "[OK] Go security check was completed!"

build: generate security
	@go build -o ./build/gos3fs main.go
	@echo "[OK] App binary was created!"

run:
	@./build/gos3fs
