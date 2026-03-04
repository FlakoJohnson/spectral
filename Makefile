# spectral build targets

BINARY  := spectral
GOOS    := linux
GOARCH  := amd64

.PHONY: all setup build clean

# First-time setup: vendor all deps then apply the go-adws proxy patch.
# Run once (or after `go mod tidy` changes deps), then use `make build`.
setup:
	go mod tidy
	go mod vendor
	go run patches/apply.go
	@echo "[+] Setup complete — run 'make build'"

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -mod=vendor -ldflags="-s -w" -trimpath -o $(BINARY) .

# Strip all debug symbols and path info for a cleaner binary.
# -s: omit symbol table, -w: omit DWARF, -trimpath: remove build paths.

clean:
	rm -f $(BINARY)

all: setup build
