//! Benchmarks

use core::{hint::black_box, time::Duration};

use aes_gcm_sst::{
    aead::{AeadInPlace, Key, KeyInit},
    Aes128GcmSst12, Aes128GcmSst14, Aes128GcmSst4, Aes128GcmSst8, Aes256GcmSst12, Aes256GcmSst14,
    Aes256GcmSst4, Aes256GcmSst8, NonceSize,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pprof::criterion::{Output, PProfProfiler};

const SIZES: &[usize] = &[
    // A small message.
    64,
    // A UDP packet.
    576,
    // A TCP packet.
    1448,
    4 * 1024,
    8 * 1024,
    16 * 1024,
];

fn bench_alg<A>(c: &mut Criterion, name: &str)
where
    A: KeyInit + AeadInPlace<NonceSize = NonceSize>,
{
    let mut group = c.benchmark_group(name);
    for size in SIZES {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_function(BenchmarkId::new("encrypt", size), |b| {
            let aead = A::new(&Key::<A>::default());
            let nonce = aead::Nonce::<A>::default();
            let mut data = vec![0; *size];
            b.iter(|| {
                let tag = black_box(&aead).encrypt_in_place_detached(
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                );
                let _ = black_box(tag);
            });
        });

        group.bench_function(BenchmarkId::new("decrypt", size), |b| {
            let aead = A::new(&Key::<A>::default());
            let nonce = aead::Nonce::<A>::default();
            let mut data = vec![0; *size];
            let tag = aead
                .encrypt_in_place_detached(&nonce, &[], &mut data)
                .unwrap();
            b.iter(|| {
                let result = black_box(&aead).decrypt_in_place_detached(
                    black_box(&nonce),
                    black_box(&[]),
                    black_box(&mut data),
                    black_box(&tag),
                );
                let _ = black_box(result);
            });
        });
    }
}

fn bench_throughput(c: &mut Criterion) {
    bench_alg::<Aes128GcmSst4>(c, "AES-128-GCM-SST-4");
    bench_alg::<Aes128GcmSst8>(c, "AES-128-GCM-SST-8");
    bench_alg::<Aes128GcmSst12>(c, "AES-128-GCM-SST-12");
    bench_alg::<Aes128GcmSst14>(c, "AES-128-GCM-SST-14");

    bench_alg::<Aes256GcmSst4>(c, "AES-256-GCM-SST-4");
    bench_alg::<Aes256GcmSst8>(c, "AES-256-GCM-SST-8");
    bench_alg::<Aes256GcmSst12>(c, "AES-256-GCM-SST-12");
    bench_alg::<Aes256GcmSst14>(c, "AES-256-GCM-SST-14");
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = bench_throughput,
}
criterion_main!(benches);
