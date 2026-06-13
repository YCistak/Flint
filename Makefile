.PHONY: all dpi cli clean

DPI_LIB := dpi/target/release/libflint_dpi.a

all: dpi cli

dpi:
	cd dpi && cargo build --release

# NOTE: Go's build cache does not hash the *contents* of static archives named
# in `#cgo LDFLAGS` (see core/dpi/handler.go).  When only libflint_dpi.a changes
# and the Go sources do not, `go build` reuses the cached cgo link and produces a
# stale binary (new mtime, old code).  We force a relink whenever the archive
# changes by folding its content hash into an (otherwise unused) -X ldflag, which
# changes the link action's cache key only when the archive actually changes —
# correct without the full-rebuild cost of `go build -a`.
cli: dpi
	go build -ldflags "-X main.dpiLibHash=$$(sha256sum $(DPI_LIB) | cut -d' ' -f1)" -o flint ./cli/...

clean:
	cd dpi && cargo clean
	rm -f flint
