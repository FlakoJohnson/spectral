# spectral build targets

BINARY  := spectral
GOOS    := linux
GOARCH  := amd64

.PHONY: all deps build clean

all: deps build

deps:
	go mod tidy

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags="-s -w" -trimpath -o $(BINARY) .

# Strip all debug symbols and path info for a cleaner binary.
# -s: omit symbol table, -w: omit DWARF, -trimpath: remove build paths.

clean:
	rm -f $(BINARY)
