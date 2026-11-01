# Ferret (Ferrum CyberSwarm) — common tasks

test:
    cargo test --workspace

lint:
    cargo clippy --workspace -- -D warnings && cargo fmt --check

run:
    cargo run -p ferrum-brain

demo:
    cargo run -p ferrum-brain -- --scenario red-team-incursion
