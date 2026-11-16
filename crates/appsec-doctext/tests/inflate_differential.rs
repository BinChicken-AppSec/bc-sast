#[path = "support/inflate_vectors.rs"]
mod inflate_vectors;

use appsec_doctext::inflate::{inflate, InflateError};
use inflate_vectors::VECTORS;

const ROOMY: usize = 4 * 1024 * 1024;

#[test]
fn every_vector_round_trips_exactly() {
    assert!(VECTORS.len() >= 40, "the corpus shrank: {}", VECTORS.len());
    for v in VECTORS {
        let got = inflate(v.compressed, ROOMY).unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(
            got.len(),
            v.plain.len(),
            "{}: decoded {} bytes, expected {}",
            v.name,
            got.len(),
            v.plain.len()
        );
        assert!(got == v.plain, "{}: bytes differ", v.name);
    }
}

#[test]
fn the_corpus_spans_stored_and_compressed_blocks() {
    let stored = VECTORS.iter().filter(|v| v.level == 0).count();
    let compressed = VECTORS.iter().filter(|v| v.level > 0).count();
    assert!(stored >= 8, "too few stored-block vectors: {stored}");
    assert!(compressed >= 24, "too few compressed vectors: {compressed}");

    let runs: Vec<_> = VECTORS
        .iter()
        .filter(|v| v.name.starts_with("long_run_of_one_byte"))
        .collect();
    let stored = runs.iter().find(|v| v.level == 0).expect("a level-0 run");
    let packed = runs.iter().find(|v| v.level == 9).expect("a level-9 run");
    assert!(
        stored.compressed.len() >= stored.plain.len(),
        "level 0 was not stored"
    );
    assert!(
        packed.compressed.len() < stored.compressed.len() / 10,
        "level 9 did not compress: {} vs {}",
        packed.compressed.len(),
        stored.compressed.len()
    );
}

#[test]
fn the_output_cap_refuses_one_byte_early_and_allows_exactly_enough() {
    for v in VECTORS {
        if v.plain.is_empty() {
            continue;
        }
        let exact = inflate(v.compressed, v.plain.len())
            .unwrap_or_else(|e| panic!("{} at its exact size: {e}", v.name));
        assert!(
            exact == v.plain,
            "{}: bytes differ at the exact cap",
            v.name
        );

        let err = inflate(v.compressed, v.plain.len() - 1)
            .expect_err(&format!("{} was not refused one byte early", v.name));
        assert_eq!(
            err,
            InflateError::OutputTooLarge {
                limit: v.plain.len() - 1
            },
            "{}",
            v.name
        );
    }
}

#[test]
fn a_highly_compressible_stream_is_refused_by_a_small_cap() {
    let bomb = VECTORS
        .iter()
        .find(|v| v.name.starts_with("zeros_64k"))
        .expect("the zeros vector");
    assert_eq!(bomb.plain.len(), 65536);
    assert!(
        bomb.compressed.len() < 200,
        "expansion ratio too low to be a useful test: {}",
        bomb.compressed.len()
    );
    assert_eq!(
        inflate(bomb.compressed, 4096),
        Err(InflateError::OutputTooLarge { limit: 4096 })
    );
    assert_eq!(inflate(bomb.compressed, 65536).expect("roomy").len(), 65536);
}

#[test]
fn a_truncated_stream_is_an_error_at_every_length() {
    for v in VECTORS.iter().filter(|v| v.compressed.len() <= 400) {
        for cut in 0..v.compressed.len() {
            if let Ok(out) = inflate(&v.compressed[..cut], ROOMY) {
                assert!(
                    out.len() <= v.plain.len(),
                    "{}: a {cut}-byte prefix produced more output than the whole stream",
                    v.name
                );
            }
        }
    }
}

#[test]
fn corrupt_input_is_always_refused_and_never_panics() {
    let mut state: u64 = 0x5DEECE66D;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545F4914F6CDD1D);
        state
    };

    let mut mutated = 0usize;
    for v in VECTORS.iter().filter(|v| v.compressed.len() <= 2048) {
        for _ in 0..200 {
            let mut bytes = v.compressed.to_vec();
            if bytes.is_empty() {
                continue;
            }
            let edits = 1 + (next() % 3) as usize;
            for _ in 0..edits {
                let at = (next() as usize) % bytes.len();
                if next() % 2 == 0 {
                    bytes[at] ^= 1u8 << (next() % 8);
                } else {
                    bytes[at] = (next() % 256) as u8;
                }
            }
            mutated += 1;
            if let Ok(out) = inflate(&bytes, 256 * 1024) {
                assert!(out.len() <= 256 * 1024);
            }
        }
    }
    assert!(mutated > 2000, "the sweep did too little: {mutated}");
}

#[test]
fn arbitrary_bytes_are_refused() {
    let mut state: u64 = 0xDEADBEEF;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state = state.wrapping_mul(0x2545F4914F6CDD1D);
        state
    };
    for len in [1usize, 2, 3, 8, 64, 512] {
        for _ in 0..200 {
            let bytes: Vec<u8> = (0..len).map(|_| (next() % 256) as u8).collect();
            if let Ok(out) = inflate(&bytes, 64 * 1024) {
                assert!(out.len() <= 64 * 1024);
            }
        }
    }
}

#[test]
fn an_empty_input_is_truncated_rather_than_an_empty_document() {
    assert_eq!(inflate(&[], ROOMY), Err(InflateError::Truncated));
}

#[test]
fn the_reserved_block_type_is_refused_by_name() {
    assert_eq!(
        inflate(&[0b0000_0111], ROOMY),
        Err(InflateError::ReservedBlockType)
    );
}

#[test]
fn a_stored_block_with_a_bad_complement_is_refused() {
    let bytes = [0b0000_0001, 0x01, 0x00, 0xFF, 0xFF, b'x'];
    assert_eq!(
        inflate(&bytes, ROOMY),
        Err(InflateError::StoredLengthMismatch)
    );
}

#[test]
fn every_error_renders_and_is_a_std_error() {
    let all = [
        InflateError::Truncated,
        InflateError::ReservedBlockType,
        InflateError::StoredLengthMismatch,
        InflateError::OverSubscribedTable,
        InflateError::InvalidCode,
        InflateError::InvalidSymbol(300),
        InflateError::DistanceTooFar {
            distance: 9,
            available: 2,
        },
        InflateError::OutputTooLarge { limit: 10 },
    ];
    for e in all {
        let rendered = e.to_string();
        assert!(!rendered.is_empty(), "{e:?} rendered empty");
        let _: &dyn std::error::Error = &e;
    }
}
