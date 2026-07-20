# Performance benchmarks & regression gate

`src/pqc.bench.ts` measures the core operations (ML-KEM-768 and X-Wing
keygen / encrypt / decrypt at 1 KiB and 100 KiB, ML-DSA-65 keygen / sign /
verify) with `vitest bench`. The `bench` job in CI runs them on every PR, prints the
numbers in the job summary, and fails only when an operation's mean exceeds
**2.5x** the committed baseline (`baseline.json`).

## Why 2.5x against a committed baseline

Absolute time thresholds flake on shared CI runners, and ratios _between_
operations are blind to global slowdowns (a regression in shared code slows
everything proportionally). Comparing each mean against a baseline measured
on the same runner class, with a generous factor, catches real algorithmic
regressions (usually ≥3x) while absorbing runner noise (±30–50%).

## Commands

```bash
pnpm bench        # run benchmarks, writes bench/results.json (gitignored)
pnpm bench:check  # compare results against bench/baseline.json (the CI gate)
```

## Updating the baseline

The baseline is only meaningful when measured on the CI runner. **Never
regenerate it locally** — means from other hardware are not comparable, and
`bench-gate.mjs` refuses to compare against nothing for the same reason.

When a PR legitimately shifts performance (algorithm change, `@noble/*`
bump, new benchmark):

1. Run the **"Bench baseline"** workflow (Actions → Bench baseline →
   Run workflow) on your PR branch.
2. Download the `bench-baseline` artifact and replace
   `packages/core/bench/baseline.json` with it, **in the same PR** that
   caused the shift.
3. The reviewer sees the old vs. new numbers in the diff and approves the
   shift explicitly — a baseline refresh is never invisible.

The gate also fails when the benchmark set differs from the baseline
(benchmarks added, removed, or renamed), which forces step 1–3 on any
benchmark change too.
