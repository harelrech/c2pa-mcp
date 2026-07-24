// Single seam through which the native @contentauth/c2pa-node binding is loaded.
// A corrupt/truncated `.node` file throws on load; routing that load through a
// caught dynamic import (instead of a static one) turns a process-crashing
// failure into a reportable status that tools can check and c2pa_info can surface.

import { createRequire } from 'node:module';

export type EngineStatus = { loaded: true } | { loaded: false; reason: string };

type NativeModule = typeof import('@contentauth/c2pa-node');

const nativeRequire = createRequire(import.meta.url);

async function defaultLoader(): Promise<NativeModule> {
  const mod = await import('@contentauth/c2pa-node');
  // @contentauth/c2pa-node lazy-loads its actual .node binary on first use
  // (its internal binary.js only calls require("./index.node") the first time
  // a Reader/Builder method runs), so a successful `import()` of the JS wrapper
  // above does NOT prove the native binary is intact. Force that load now, via
  // the same file its own lazy loader would require, so a corrupt/truncated
  // .node file is caught here instead of surfacing later as a generic per-file
  // verification error. Coupled to c2pa-node's internal dist/index.node layout;
  // package.json pins an exact version so this stays in sync deliberately.
  nativeRequire(nativeRequire.resolve('@contentauth/c2pa-node/dist/index.node'));
  return mod;
}

let loaderOverride: (() => Promise<NativeModule>) | null = null;
/** Test-only seam: override how the native module is loaded. */
export function setEngineLoaderForTest(fn: (() => Promise<NativeModule>) | null): void {
  loaderOverride = fn;
}

let cached: { status: EngineStatus; mod: NativeModule | null } | null = null;
/** Test-only seam: force the next call to re-probe instead of reusing the cache. */
export function resetEngineCacheForTest(): void {
  cached = null;
}

// Process-lifetime memo: if the binding failed to load once, re-importing the same
// broken file will not succeed without a reinstall (which requires a process
// restart anyway), so a single-shot cache is correct, not just an optimization.
async function loadOnce(): Promise<{ status: EngineStatus; mod: NativeModule | null }> {
  if (cached) return cached;
  try {
    const mod = await (loaderOverride ? loaderOverride() : defaultLoader());
    cached = { status: { loaded: true }, mod };
  } catch (err) {
    cached = {
      status: { loaded: false, reason: (err as Error).message || 'unknown load error' },
      mod: null,
    };
  }
  return cached;
}

/** Probe (or reuse the cached probe of) the native engine. Never throws. */
export async function getEngineStatus(): Promise<EngineStatus> {
  return (await loadOnce()).status;
}

/** Resolve the loaded native module, or throw a labeled error if it failed to load. */
export async function requireEngine(): Promise<NativeModule> {
  const { status, mod } = await loadOnce();
  if (!status.loaded) throw new Error(`engine failed to load: ${status.reason}`);
  return mod as NativeModule;
}
