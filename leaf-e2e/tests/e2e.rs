//! Entry point for the end-to-end suite. The harness owns argument parsing and
//! process-per-case isolation, so this only hands control to it; see the
//! crate's README for how to run and filter it.

fn main() {
    leaf_e2e::runner::main()
}
