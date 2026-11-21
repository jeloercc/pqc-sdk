// Test-only child-process instrumentation. Retaining references changes liveness;
// these checks establish visible buffer contents, not physical erasure or timing.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import process from 'node:process';

import { Keccak } from '@noble/hashes/sha3.js';

const vendor = await import('../src/vendor/ml-kem/ml-kem.ts');
const references = JSON.parse(
  readFileSync(new URL('../src/vectors/acvp/ml-kem/encapdecap.json', import.meta.url), 'utf8'),
);
const keys = JSON.parse(
  readFileSync(new URL('../src/vectors/acvp/ml-kem/keygen.json', import.meta.url), 'utf8'),
);
const mode = process.argv[2];
assert.ok(['sampling', 'outer', 'polynomial'].includes(mode));
const Native8 = globalThis.Uint8Array,
  Native16 = globalThis.Uint16Array;
const original = {
  update: Keccak.prototype.update,
  digest: Keccak.prototype.digest,
  slice: Native16.prototype.slice,
};
const hex = (s) => Native8.from(Buffer.from(s, 'hex'));
const nonzero = (a) => a.some((v) => v !== 0);
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const stack = () => new Error().stack ?? '';
const sourceSite = (trace) =>
  trace.split('\n').find((line) => line.includes('/src/vendor/ml-kem/')) ?? '';
const sentinel = new Error('Synthetic cleanup-test fault');
let active;
const failures = [],
  controlErrors = [],
  records = [],
  controls = [];

function polyRole(trace, copied) {
  if (trace.includes('sampleCBDBytes')) return 'noise-poly';
  if (trace.includes('SampleNTT') || (copied && trace.includes('encryptCore')))
    return 'matrix-product';
  if (trace.includes('Object.decrypt')) return 'decrypt-poly';
  return copied ? 'public-copy' : 'polynomial';
}
function beforeAllocation(role) {
  if (!active) return;
  const count = (active.counts[role] = (active.counts[role] ?? 0) + 1);
  if (active.fault?.target === role && active.fault.nth === count) {
    active.injected = true;
    throw sentinel;
  }
}
function retainPoly(ref, role, trace) {
  // Modulus validation decodes public key coefficients; they are not secret scratch.
  if (active && sourceSite(trace) && !trace.includes('validateModulus')) active.polys.push({ ref, role });
  return ref;
}

try {
  Keccak.prototype.update = function (data) {
    if (active && this.suffix === 0x06 && this.outputLen === 64 && this.pos === 0) {
      active.values.push({
        ref: data,
        role:
          active.operation === 'keygen'
            ? 'seed-copy'
            : active.operation === 'decapsulate'
              ? 'message'
              : 'borrowed-message',
      });
    }
    return original.update.call(this, data);
  };
  Keccak.prototype.digest = function () {
    const suffix = this.suffix,
      length = this.outputLen;
    const out = original.digest.call(this);
    if (active) {
      const role =
        suffix === 0x1f && [128, 192].includes(length)
          ? 'prf'
          : suffix === 0x06 && length === 64
            ? 'digest'
            : suffix === 0x1f && length === 32
              ? 'alternate'
              : 'public';
      const item = { ref: out, role, owned: true };
      active.values.push(item);
      if (active.fault?.target === 'late' && role === 'alternate') {
        // This output never transfers to the wrapper; exclude it from caller cleanup.
        item.owned = false;
        active.injected = true;
        throw sentinel;
      }
    }
    return out;
  };
  globalThis.Uint16Array = new Proxy(Native16, {
    construct(target, args) {
      const trace = active ? stack() : '';
      const role = polyRole(trace, false);
      if (sourceSite(trace)) beforeAllocation(role);
      return retainPoly(Reflect.construct(target, args, target), role, trace);
    },
  });
  Native16.prototype.slice = function (...args) {
    const trace = active ? stack() : '';
    const role = polyRole(trace, true);
    if (sourceSite(trace)) beforeAllocation(role);
    return retainPoly(original.slice.apply(this, args), role, trace);
  };
  globalThis.Uint8Array = new Proxy(Native8, {
    construct(target, args) {
      if (active) {
        const trace = stack(),
          site = sourceSite(trace);
        if (site.includes('selectSharedSecret')) beforeAllocation('select');
        if (
          site.includes('/utils.ts') &&
          site.includes('encode') &&
          (trace.includes('encryptCore') || active.operation === 'keygen')
        )
          beforeAllocation('encode');
      }
      return Reflect.construct(target, args, target);
    },
  });

  for (const bits of [512, 768, 1024]) {
    const k = { 512: 2, 768: 3, 1024: 4 }[bits];
    const kem = vendor[`ml_kem${bits}`];
    const group = references.testGroups.find(
      (g) => g.parameterSet === `ML-KEM-${bits}` && g.function === 'decapsulation',
    );
    const enc = references.testGroups.find(
      (g) => g.parameterSet === `ML-KEM-${bits}` && g.function === 'encapsulation',
    ).tests[0];
    const key = keys.testGroups.find((g) => g.parameterSet === `ML-KEM-${bits}`).tests[0];
    const operations =
      mode === 'polynomial' ? ['decapsulate', 'encapsulate', 'keygen'] : ['decapsulate'];
    for (const operation of operations) {
      for (const path of operation === 'keygen' ? ['ordinary'] : ['ordinary', 'prepared']) {
        const normal =
          operation === 'decapsulate'
            ? ['valid decapsulation', 'modified ciphertext']
            : ['valid decapsulation'];
        const scenarios = normal.map((reason) => ({ reason }));
        if (mode === 'sampling')
          scenarios.push({ reason: normal[0], fault: { target: 'noise-poly', nth: 1 } });
        if (mode === 'outer')
          scenarios.push(
            ...['late', 'select'].map((target) => ({
              reason: normal[0],
              fault: { target, nth: 1 },
            })),
          );
        if (mode === 'polynomial') {
          for (const target of ['noise-poly', 'matrix-product']) {
            const limit =
              target === 'noise-poly' ? (operation === 'keygen' ? 2 * k : 2 * k + 1) : k * k;
            for (const nth of new Set([1, Math.ceil(limit / 2), limit]))
              scenarios.push({ reason: normal[0], fault: { target, nth } });
          }
          scenarios.push({ reason: normal[0], fault: { target: 'encode', nth: 1 } });
          if (operation === 'decapsulate')
            for (const nth of [2, k + 1, 2 * k + 1])
              scenarios.push({ reason: normal[0], fault: { target: 'decrypt-poly', nth } });
        }
        for (const scenario of scenarios) {
          const reference = group.tests.find((t) => t.reason === scenario.reason);
          const sk = hex(reference.dk),
            ct = hex(reference.c),
            pk = hex(operation === 'encapsulate' ? enc.ek : reference.ek);
          const msg = hex(enc.m),
            seed = new Native8([...hex(key.d), ...hex(key.z)]);
          const inputs = [sk, ct, pk, msg, seed],
            snapshots = inputs.map((a) => a.slice());
          const prepared = path === 'prepared' ? kem.prepare(pk) : null;
          const context = {
            operation,
            fault: scenario.fault,
            injected: false,
            values: [],
            polys: [],
            counts: {},
          };
          let out, caught;
          active = context;
          try {
            out =
              operation === 'decapsulate'
                ? (prepared ?? kem).decapsulate(ct, sk)
                : operation === 'encapsulate'
                  ? prepared
                    ? prepared.encapsulate(msg)
                    : kem.encapsulate(pk, msg)
                  : kem.keygen(seed);
          } catch (error) {
            caught = error;
          }
          active = undefined;
          // No test-side cleanup is allowed before recording contents and preservation.
          const id = {
            bits,
            operation,
            path,
            fault: scenario.fault ?? null,
            reason: scenario.reason,
          };
          if (scenario.fault ? !context.injected || caught !== sentinel || out : caught || !out)
            controlErrors.push({ ...id, issue: 'operation/fault control' });
          if (!inputs.every((a, i) => same(a, snapshots[i])))
            controlErrors.push({ ...id, issue: 'borrowed input mutated' });
          if (!scenario.fault && out) {
            const correct =
              operation === 'decapsulate'
                ? same(out, hex(reference.k))
                : operation === 'encapsulate'
                  ? same(out.cipherText, hex(enc.c)) && same(out.sharedSecret, hex(enc.k))
                  : same(out.publicKey, hex(key.ek)) && same(out.secretKey, hex(key.dk));
            if (!correct) controlErrors.push({ ...id, issue: 'official output mismatch' });
          }
          const prfs = context.values.filter((v) => v.role === 'prf');
          if (!scenario.fault && prfs.length !== (operation === 'keygen' ? 2 * k : 2 * k + 1))
            controlErrors.push({ ...id, issue: 'PRF count' });
          const expectedPolys = operation === 'keygen' ? k * k + 2 * k
            : operation === 'decapsulate' ? k * k + 6 * k + 5 : k * k + 4 * k + 3;
          if (!scenario.fault && context.polys.length !== expectedPolys)
            controlErrors.push({ ...id, issue: 'polynomial count', actual: context.polys.length, expected: expectedPolys });
          if (mode === 'sampling' && !prfs.length)
            controlErrors.push({ ...id, issue: 'empty PRF observation' });
          if (mode === 'polynomial' && !context.polys.length && operation !== 'keygen')
            controlErrors.push({ ...id, issue: 'empty polynomial observation' });
          if (mode === 'outer' && context.values.filter((v) => v.role === 'message').length !== 1)
            controlErrors.push({ ...id, issue: 'message observation' });
          const pending =
            mode === 'sampling'
              ? prfs
              : mode === 'polynomial'
                ? [
                    ...context.polys,
                    ...context.values.filter(
                      (v) => operation === 'keygen' && ['digest', 'seed-copy'].includes(v.role),
                    ),
                  ]
                : context.values.filter(
                    (v) => ['message', 'digest', 'alternate'].includes(v.role) && v.owned !== false,
                  );
          const remaining = pending.filter((v) => nonzero(v.ref));
          if (!pending.length) controlErrors.push({ ...id, issue: 'empty owned-buffer observation' });
          if (remaining.length)
            failures.push({
              ...id,
              issue: 'owned buffers not cleared',
              count: remaining.length,
              roles: [...new Set(remaining.map((v) => v.role))],
            });
          records.push({
            ...id,
            prfs: prfs.length,
            polynomials: context.polys.length,
            observed: pending.length,
            uncleared: remaining.length,
          });
          if (prepared) {
            const recovered =
              operation === 'decapsulate'
                ? prepared.decapsulate(hex(reference.c), sk)
                : prepared.encapsulate(msg);
            const match =
              operation === 'decapsulate'
                ? same(recovered, hex(reference.k))
                : same(recovered.cipherText, hex(enc.c)) &&
                  same(recovered.sharedSecret, hex(enc.k));
            if (!match) controlErrors.push({ ...id, issue: 'prepared reuse' });
          }
          for (const v of [...context.values, ...context.polys]) v.ref.fill(0);
          prepared?.clean();
          controls.push({ bits, operation, path, reference, enc, key });
        }
      }
    }
  }
} finally {
  active = undefined;
  Keccak.prototype.update = original.update;
  Keccak.prototype.digest = original.digest;
  Native16.prototype.slice = original.slice;
  globalThis.Uint8Array = Native8;
  globalThis.Uint16Array = Native16;
}
assert.equal(Keccak.prototype.update, original.update);
assert.equal(Keccak.prototype.digest, original.digest);
assert.equal(globalThis.Uint16Array, Native16);
assert.equal(globalThis.Uint8Array, Native8);
assert.equal(Native16.prototype.slice, original.slice);
for (const { bits, operation, path, reference, enc, key } of controls) {
  const kem = vendor[`ml_kem${bits}`],
    prepared =
      path === 'prepared'
        ? kem.prepare(hex(operation === 'encapsulate' ? enc.ek : reference.ek))
        : null;
  const out =
    operation === 'decapsulate'
      ? (prepared ?? kem).decapsulate(hex(reference.c), hex(reference.dk))
      : operation === 'encapsulate'
        ? prepared
          ? prepared.encapsulate(hex(enc.m))
          : kem.encapsulate(hex(enc.ek), hex(enc.m))
        : kem.keygen(new Native8([...hex(key.d), ...hex(key.z)]));
  const match =
    operation === 'decapsulate'
      ? same(out, hex(reference.k))
      : operation === 'encapsulate'
        ? same(out.cipherText, hex(enc.c)) && same(out.sharedSecret, hex(enc.k))
        : same(out.publicKey, hex(key.ek)) && same(out.secretKey, hex(key.dk));
  if (!match) controlErrors.push({ bits, operation, path, issue: 'uninstrumented output' });
  prepared?.clean();
}
process.stdout.write(
  JSON.stringify({
    mode,
    records,
    failures,
    controlErrors,
    hooksRestored: true,
    uninstrumentedControls: controls.length,
  }) + '\n',
);
