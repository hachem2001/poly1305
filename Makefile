zip:
	rm -f mohamed.ouertani.td2.zip
	zip -r mohamed.ouertani..td2.zip . -i README.md src/ Makefile Cargo.toml

all:
	cargo build --release
	mkdir -p release
	rm -f release/poly1305-check release/poly1305-gen
	cp target/release/poly1305-check release/poly1305-check
	cp target/release/poly1305-gen release/poly1305-gen

test: all
	file=$(mktemp)
	echo "Input : Cryptographic Forum Research Group"
	echo -n "Cryptographic Forum Research Group" > $file
