//! Criterion benchmarks: `cargo bench -p ed521 --features __bench,__hazmat-sign,batch`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ed521::bench_internals::{Fe, Split, base, challenge, decompress, double_base};
use ed521::hazmat::SigningKey;
use ed521::{Mode, VerifyingKey};

fn field(c: &mut Criterion) {
    let mut group = c.benchmark_group("field");
    let a = Fe::from_bytes(&[0x5A; 66]);
    let b = Fe::from_bytes(&[0xC3; 66]);
    group.bench_function("mul", |bench| bench.iter(|| black_box(&a).mul(black_box(&b))));
    group.bench_function("square", |bench| bench.iter(|| black_box(&a).square()));
    {
        use fiat_crypto::p521_64::{
            fiat_p521_carry_mul, fiat_p521_carry_square, fiat_p521_loose_field_element,
            fiat_p521_tight_field_element,
        };
        let fa = fiat_p521_loose_field_element([0x0155_5555_5555_5555; 9]);
        let fb = fiat_p521_loose_field_element([0x0233_3333_3333_3333; 9]);
        let mut out = fiat_p521_tight_field_element([0; 9]);
        group.bench_function("fiat_mul", |bench| {
            bench.iter(|| {
                fiat_p521_carry_mul(&mut out, black_box(&fa), black_box(&fb));
                out.0[0]
            });
        });
        group.bench_function("fiat_square", |bench| {
            bench.iter(|| {
                fiat_p521_carry_square(&mut out, black_box(&fa));
                out.0[0]
            });
        });
    }
    #[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
    if ed521::bench_internals::avx2::available() {
        let (va, vb) = (ed521::bench_internals::avx2::fe(&a), ed521::bench_internals::avx2::fe(&b));
        group
            .bench_function("avx2_mul4", |bench| bench.iter(|| black_box(&va).mul(black_box(&vb))));
        group.bench_function("avx2_square4", |bench| bench.iter(|| black_box(&va).square()));
    }
    group.bench_function("invert", |bench| bench.iter(|| black_box(&a).invert()));
    group.finish();
}

fn point(c: &mut Criterion) {
    let mut group = c.benchmark_group("point");
    let p = base().double();
    let q = p.double().add(&base());
    let encoded = q.compress();
    group.bench_function("double", |bench| bench.iter(|| black_box(&p).double()));
    group.bench_function("add", |bench| bench.iter(|| black_box(&p).add(black_box(&q))));
    group.bench_function("decompress", |bench| bench.iter(|| decompress(black_box(&encoded))));
    let (k, s) = ([0xA7u8; 66], [0x3Cu8; 66]);
    group.bench_function("double_base", |bench| {
        bench.iter(|| double_base(black_box(&k), black_box(&q), black_box(&s)));
    });
    let split8 = Split::<8>::new(&q);
    let split16 = Split::<16>::new(&q);
    group.bench_function("split_tables_8", |bench| bench.iter(|| Split::<8>::new(black_box(&q))));
    for b_width in [6, 7, 8] {
        group.bench_function(format!("double_base_split_a5_b{b_width}"), |bench| {
            bench.iter(|| split8.double_base(black_box(&k), black_box(&s), b_width));
        });
        group.bench_function(format!("double_base_split_a6_b{b_width}"), |bench| {
            bench.iter(|| split16.double_base(black_box(&k), black_box(&s), b_width));
        });
    }
    group.bench_function("challenge_64", |bench| {
        bench.iter(|| challenge(black_box(&encoded), black_box(&encoded), black_box(&[7u8; 64])));
    });
    group.finish();
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");
    let signer = SigningKey::from_ecpy_private(&[0x42; 66]);
    let message = [0x11u8; 64];
    let signature = signer.sign(&message);
    let key_bytes = signer.verifying_key().to_bytes();
    let key = VerifyingKey::from_bytes(&key_bytes).unwrap();
    group.bench_function("decode_key", |bench| {
        bench.iter(|| VerifyingKey::from_bytes_with_mode(black_box(&key_bytes), Mode::Strict));
    });
    group.bench_function("verify", |bench| {
        bench.iter(|| key.verify(black_box(&message), black_box(&signature)));
    });
    let precomputed = key.precompute();
    group.bench_function("precompute", |bench| bench.iter(|| black_box(&key).precompute()));
    group.bench_function("verify_precomputed", |bench| {
        bench.iter(|| precomputed.verify(black_box(&message), black_box(&signature)));
    });
    let messages: Vec<[u8; 64]> = (0..64u8).map(|i| [i; 64]).collect();
    let signatures: Vec<_> = messages.iter().map(|m| signer.sign(m)).collect();
    let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let mut results = vec![Ok(()); 64];
    group.throughput(criterion::Throughput::Elements(64));
    group.bench_function("verify_many_64", |bench| {
        bench.iter(|| key.verify_many(black_box(&refs), black_box(&signatures), &mut results));
    });
    group.bench_function("verify_many_precomputed_64", |bench| {
        bench.iter(|| {
            precomputed.verify_many(black_box(&refs), black_box(&signatures), &mut results);
        });
    });
    group.finish();
}

/// The urn shape: one key, 12 signatures. Per-signature throughput.
fn batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("urn12");
    let signer = SigningKey::from_ecpy_private(&[0x42; 66]);
    let messages: Vec<[u8; 64]> = (0..12u8).map(|i| [i; 64]).collect();
    let signatures: Vec<_> = messages.iter().map(|m| signer.sign(m)).collect();
    let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let key_bytes = signer.verifying_key().to_bytes();
    let mut results = vec![Ok(()); 12];
    group.throughput(criterion::Throughput::Elements(12));
    group.bench_function("decode_precompute_verify_many", |bench| {
        bench.iter(|| {
            let key = VerifyingKey::from_bytes(black_box(&key_bytes)).unwrap().precompute();
            key.verify_many(&refs, &signatures, &mut results);
        });
    });
    group.bench_function("decode_verify_batch", |bench| {
        bench.iter(|| {
            let key = VerifyingKey::from_bytes(black_box(&key_bytes)).unwrap();
            key.verify_batch(&refs, &signatures)
        });
    });
    let precomputed = VerifyingKey::from_bytes(&key_bytes).unwrap().precompute();
    group.bench_function("precomputed_verify_batch", |bench| {
        bench.iter(|| precomputed.verify_batch(black_box(&refs), &signatures));
    });
    group.finish();
}

criterion_group!(benches, field, point, verify, batch);
criterion_main!(benches);
