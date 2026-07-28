.PHONY: build test check verify-self clean

build:
	cargo build --release

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo check

verify-self:
	cargo build --release 2>/dev/null; \
	./target/release/veriscan verify ./target/release/veriscan --policy policies/default.yaml; \
	echo "Exit: $$?"

clean:
	cargo clean
