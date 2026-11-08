# ed521rs development recipes.

python := ".venv/bin/python"
export PYO3_PYTHON := justfile_directory() / ".venv/bin/python"

_default:
    @just --list

# Create the Python dev environment (maturin, ruff, ty, asn1tools and the ECPy oracle).
setup:
    uv venv --python 3.14 .venv
    uv pip install --python {{python}} --group dev --group tse --group oracle

fmt:
    cargo fmt --all
    .venv/bin/ruff format scripts tests/python python

lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    .venv/bin/ruff check scripts tests/python python
    .venv/bin/ty check

test:
    cargo test --workspace --all-features
    RUSTFLAGS='--cfg ed521_backend="serial"' CARGO_TARGET_DIR=target/serial cargo test -p ed521 --all-features
    cargo test -p ed521 --no-default-features

# The library on its MSRV (the dev-dependencies need a newer compiler, so this builds only).
test-msrv:
    cargo +1.87 build -p ed521 --all-features
    cargo +1.87 build -p ed521 --no-default-features

test-nostd:
    cargo build -p ed521 --no-default-features

# Build the extension into .venv and run the Python suite.
py-test:
    .venv/bin/maturin develop --release -q
    {{python}} -m unittest discover -s tests/python -v

# The long random parity run (10000 cases against the pure-Python reference).
py-parity:
    ED521RS_PARITY_CASES=10000 {{python}} -m unittest tests/python/test_ed521rs.py -k Parity

# Regenerate the generated tables, kernels and edge cases and require that nothing changed.
vectors:
    {{python}} -I scripts/gen_tables.py --check
    {{python}} -I scripts/gen_edge_cases.py --check
    {{python}} -I scripts/gen_avx2_kernels.py --check

# Download TSE's original files into tse-sources/ (some need a browser; the script says which).
tse-fetch downloads="~/Downloads":
    {{python}} -I scripts/tse_vectors.py fetch --browser-downloads {{downloads}}

# Rebuild crates/ed521/tests/vectors/tse-2026.json from tse-sources/ and require no change.
tse-vectors:
    {{python}} -I scripts/tse_vectors.py extract --check

# Differential fuzzing against the big-integer model in fuzz/src (nightly, cargo-fuzz).
fuzz seconds="600":
    cd fuzz && cargo +nightly fuzz run -O decode -- -max_total_time={{seconds}} -max_len=66
    cd fuzz && cargo +nightly fuzz run -O verify -- -max_total_time={{seconds}} -max_len=400
    cd fuzz && cargo +nightly fuzz run -O batch -- -max_total_time={{seconds}} -max_len=32

bench:
    cargo bench -p ed521 --features __bench,__hazmat-sign,batch --bench ed521

check: lint test test-nostd test-msrv vectors py-test
