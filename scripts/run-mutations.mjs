#!/usr/bin/env node

/**
 * Replays the Exhibit 7 §4.1c ledger in an isolated archive of committed HEAD.
 * A mutation is killed only after all five required observations occur:
 * baseline green, non-empty source diff, moved bundle, named test red, and
 * byte-identical restoration with the named test green. No result is typed in.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const ledger = JSON.parse(readFileSync(join(root, 'e2e', 'verdict-mutations.json'), 'utf8'));
const selected = process.argv.slice(2);
const mutations = selected.length
  ? ledger.mutations.filter((entry) => selected.includes(entry.id))
  : ledger.mutations;

if (selected.some((id) => !ledger.mutations.some((entry) => entry.id === id))) {
  console.error('Unknown mutation id. Run without arguments to execute the full ledger.');
  process.exit(2);
}

function run(command, args, cwd, allowFailure = false) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, CI: '1', FORCE_COLOR: '0' },
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (!allowFailure && result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.status})\n${output}`);
  }
  return { status: result.status, output };
}

const git = (...args) => run('git', ['-C', root, ...args], root).output.trim();
const trackedDirty = git('status', '--porcelain', '--untracked-files=no');
if (trackedDirty) {
  console.error('Refusing to mutate: commit the real implementation first.');
  console.error(trackedDirty);
  process.exit(2);
}

for (const entry of mutations) {
  const source = readFileSync(join(root, entry.file), 'utf8');
  const count = source.split(entry.find).length - 1;
  if (count !== 1) {
    console.error(`${entry.id}: anchor occurs ${count} times in ${entry.file}; expected exactly once.`);
    process.exit(2);
  }
  if (source.replace(entry.find, entry.replace) === source) {
    console.error(`${entry.id}: patch is a no-op.`);
    process.exit(2);
  }
}

const tree = mkdtempSync(join(tmpdir(), 'frost-ats-mutations-'));
const archive = join(tree, 'source.tar');

function digest(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

function fileHash(path) {
  return digest(readFileSync(path));
}

function bundleHash() {
  const assets = join(tree, 'dist', 'assets');
  if (!existsSync(assets)) throw new Error('dist/assets does not exist after a reported successful build');
  const hash = createHash('sha256');
  for (const name of readdirSync(assets).sort()) {
    hash.update(name);
    hash.update(readFileSync(join(assets, name)));
  }
  return hash.digest('hex').slice(0, 12);
}

function build() {
  run('npm', ['run', 'build'], tree);
  return bundleHash();
}

function owningTest(entry, expectGreen) {
  const result = run(
    'npx',
    [
      'playwright',
      'test',
      'e2e/claims.spec.ts',
      '-g',
      entry.test,
      '--retries=0',
      '--reporter=list',
    ],
    tree,
    !expectGreen,
  );
  if (expectGreen && result.status !== 0) {
    throw new Error(`${entry.id}: unmutated/restored owning test is red\n${result.output}`);
  }
  if (!expectGreen) {
    if (result.status === 0) throw new Error(`${entry.id}: mutation SURVIVED; named test stayed green`);
    if (!result.output.includes(entry.test)) {
      throw new Error(`${entry.id}: suite went red without naming its owning test\n${result.output}`);
    }
    if (/error TS\d+|Build failed|Process from config\.webServer was not able to start/i.test(result.output)) {
      throw new Error(`${entry.id}: red result was a build/server failure, not a mutation kill\n${result.output}`);
    }
  }
}

function replaceExactly(path, from, to) {
  const source = readFileSync(path, 'utf8');
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${path}: replacement anchor occurs ${count} times`);
  const changed = source.replace(from, to);
  if (changed === source) throw new Error(`${path}: source diff was empty`);
  writeFileSync(path, changed);
}

let failures = 0;
try {
  run('git', ['archive', '--format=tar', `--output=${archive}`, 'HEAD'], root);
  run('tar', ['-xf', archive, '-C', tree], root);
  unlinkSync(archive);
  symlinkSync(join(root, 'node_modules'), join(tree, 'node_modules'));
  symlinkSync(join(root, 'pkg'), join(tree, 'pkg'));

  console.log(`Committed tree: ${git('rev-parse', '--short', 'HEAD')}`);
  console.log(`Mutations: ${mutations.length}\n`);

  const baselineBundle = build();

  for (const entry of mutations) {
    const path = join(tree, entry.file);
    const sourceBefore = fileHash(path);
    console.log(`${entry.id}`);
    try {
      owningTest(entry, true);
      console.log(`  1 baseline PASSES — ${entry.test}`);

      replaceExactly(path, entry.find, entry.replace);
      const sourceAfter = fileHash(path);
      if (sourceAfter === sourceBefore) throw new Error('source diff is empty');
      console.log(`  2 source diff NON-EMPTY — ${sourceBefore} -> ${sourceAfter}`);

      const mutatedBundle = build();
      if (mutatedBundle === baselineBundle) throw new Error('production bundle hash did not move');
      console.log(`  3 bundle hash MOVED — ${baselineBundle} -> ${mutatedBundle}`);

      owningTest(entry, false);
      console.log(`  4 NAMED test RED — ${entry.test}`);

      replaceExactly(path, entry.replace, entry.find);
      if (fileHash(path) !== sourceBefore) throw new Error('source did not restore byte-for-byte');
      const restoredBundle = build();
      if (restoredBundle !== baselineBundle) throw new Error('restored bundle hash differs from baseline');
      owningTest(entry, true);
      console.log(`  5 restored and GREEN — bundle ${restoredBundle}\n`);
    } catch (error) {
      failures += 1;
      console.error(`  FAILED: ${error instanceof Error ? error.message : String(error)}\n`);
      const current = readFileSync(path, 'utf8');
      if (current.includes(entry.replace) && !current.includes(entry.find)) {
        replaceExactly(path, entry.replace, entry.find);
      }
    }
  }
} finally {
  rmSync(tree, { recursive: true, force: true });
}

console.log(`${mutations.length - failures}/${mutations.length} mutations killed.`);
process.exit(failures === 0 ? 0 : 1);
