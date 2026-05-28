.PHONY: all dpi cli clean

all: dpi cli

dpi:
	cd dpi && cargo build --release

cli: dpi
	go build -o flint ./cli/...

clean:
	cd dpi && cargo clean
	rm -f flint
