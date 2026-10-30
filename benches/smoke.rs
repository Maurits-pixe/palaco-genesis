use criterion::{criterion_group, criterion_main, Criterion};
use palaco_genesis::healthcheck;

fn bench_healthcheck(c: &mut Criterion) {
    c.bench_function("healthcheck", |b| b.iter(healthcheck));
}

criterion_group!(benches, bench_healthcheck);
criterion_main!(benches);
