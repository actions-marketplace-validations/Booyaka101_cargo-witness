'use strict';
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const { KEY } = require('./publish-age');

/**
 * Read and write `registry.global-min-publish-age` in `.cargo/config.toml`
 * without disturbing the rest of the file.
 *
 * The edit is line-based on purpose. Parsing the TOML and re-serialising it
 * would drop every comment, blank line and key order in a file the user owns
 * and shares with cargo, so the writer touches only the one assignment (or
 * inserts one) and leaves every other byte, including the EOL style, exactly as
 * it found it.
 *
 * cargo accepts both spellings of the same key, the `[registry]` table and a
 * top-level dotted `registry.global-min-publish-age = "..."`, and TOML forbids
 * mixing them: appending a `[registry]` table to a file that already carries
 * ANY top-level `registry.` dotted key makes cargo refuse to load the config at
 * all ("could not parse TOML configuration", exit 101, verified against cargo
 * 1.95). So the writer matches whichever spelling is already there and only
 * appends a table when neither exists.
 *
 * RFC 3923 defers a per-package exclude list to future work and cargo ships no
 * key for one, so exclusions are round-tripped through a marker comment rather
 * than invented as a cargo key: the file stays valid for cargo, and
 * cargo-witness reads its own list back.
 */

const TABLE = 'registry';
const BARE_KEY = 'global-min-publish-age';
const EXCLUDE_MARKER = '# cargo-witness-exclude = ';
// Setting this to "allow" turns cargo's resolver gate off, which would leave
// the threshold we write doing nothing. Worth saying out loud, never touched.
const RESOLVER_TABLE = 'resolver';
const RESOLVER_KEY = 'incompatible-publish-age';

// The value is captured greedily and trimmed in JS. A lazy `(.+?)\s*$` makes
// the engine re-scan the trailing whitespace for every split of the group,
// which is quadratic on a pathological line (CodeQL js/polynomial-redos).
const dottedRe = (table, key) =>
  new RegExp(`^\\s*${table}\\s*\\.\\s*${key}\\s*=(.*)$`);
const bareRe = (key) => new RegExp(`^\\s*${key}\\s*=(.*)$`);
// Any top-level `registry.` dotted key at all, ours or not: its presence rules
// out ever appending a `[registry]` table.
const ANY_REGISTRY_DOTTED = new RegExp(`^\\s*${TABLE}\\s*\\.\\s*[^\\s=]+\\s*=`);

/** Table header a line opens, or null. `[a.b]` and `[[a]]` both counted. */
function tableOf(line) {
  const m = line.trim().match(/^\[\[?([^\]]+)\]\]?\s*$/);
  return m ? m[1].trim() : null;
}

/**
 * Walk the file once and record everything both the reader and the writer need:
 * where our key is and how it is spelled, where the `[registry]` table opens,
 * where the last top-level `registry.` dotted key sits, the resolver mode, and
 * any exclusion marker. One walk, one set of patterns, so the two callers
 * cannot drift apart.
 */
function locate(lines) {
  const at = {
    keyIndex: -1, value: null, dotted: false,
    tableIndex: -1, lastDottedIndex: -1,
    resolverMode: null, excludes: [], markerIndexes: [],
  };
  let table = null;

  lines.forEach((line, i) => {
    const t = tableOf(line);
    if (t !== null) {
      table = t;
      if (t === TABLE && at.tableIndex < 0) at.tableIndex = i;
      return;
    }
    if (line.trimStart().startsWith(EXCLUDE_MARKER)) {
      at.markerIndexes.push(i);
      const raw = line.trimStart().slice(EXCLUDE_MARKER.length).trim();
      try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) for (const n of arr) if (typeof n === 'string') at.excludes.push(n);
      } catch { /* a hand-edited marker is not an error; treat it as absent */ }
      return;
    }

    if (table === null) {
      if (ANY_REGISTRY_DOTTED.test(line)) at.lastDottedIndex = i;
      const d = line.match(dottedRe(TABLE, BARE_KEY));
      if (d && at.keyIndex < 0) {
        at.keyIndex = i; at.dotted = true; at.value = readValue(d[1]);
      }
      const r = line.match(dottedRe(RESOLVER_TABLE, RESOLVER_KEY));
      if (r && at.resolverMode === null) at.resolverMode = readValue(r[1]);
      return;
    }
    if (table === RESOLVER_TABLE && at.resolverMode === null) {
      const r = line.match(bareRe(RESOLVER_KEY));
      if (r) at.resolverMode = readValue(r[1]);
      return;
    }
    if (table === TABLE && at.keyIndex < 0) {
      const m = line.match(bareRe(BARE_KEY));
      if (m) { at.keyIndex = i; at.dotted = false; at.value = readValue(m[1]); }
    }
  });

  return at;
}

/**
 * Current state of the file.
 * @returns {{exists:boolean, value:string|null, dotted:boolean, excludes:string[],
 *   eol:string, lines:string[], trailingNewline:boolean, resolverMode:string|null}}
 */
function readCargoConfig(configPath) {
  let text = null;
  try {
    text = fs.readFileSync(configPath, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const exists = text !== null;
  const eol = exists && text.includes('\r\n') ? '\r\n' : '\n';
  const trailingNewline = !exists || text === '' || /\r?\n$/.test(text);
  const lines = exists ? text.split(/\r?\n/) : [];
  // split() on a trailing newline leaves an empty last element; drop it and
  // re-add the newline on write so the file's own ending is preserved.
  if (exists && trailingNewline && lines.length && lines[lines.length - 1] === '') lines.pop();

  const at = locate(lines);
  return {
    exists,
    value: at.value,
    dotted: at.dotted,
    excludes: at.excludes,
    resolverMode: at.resolverMode,
    eol,
    lines,
    trailingNewline,
  };
}

/** A captured assignment right-hand side, minus any comment and quotes. */
function readValue(raw) {
  return unquote(stripComment(raw));
}

/** Drop a trailing `# ...` comment from a TOML value, respecting quotes. */
function stripComment(v) {
  let inStr = false;
  for (let i = 0; i < v.length; i++) {
    if (v[i] === '"') inStr = !inStr;
    else if (v[i] === '#' && !inStr) return v.slice(0, i).trim();
  }
  return v.trim();
}

function unquote(v) {
  return v.length >= 2 && v.startsWith('"') && v.endsWith('"') ? v.slice(1, -1) : v;
}

/**
 * Set the key to `duration` and record `excludes`, preserving everything else.
 *
 * @returns {{written:boolean, created:boolean, previous:string|null,
 *   previousExcludes:string[], dotted:boolean, value:string, path:string}}
 */
function writeCargoConfig(configPath, duration, excludes = []) {
  const st = readCargoConfig(configPath);
  const list = [...new Set(excludes)];
  const marker = `${EXCLUDE_MARKER}${JSON.stringify(list)}`;

  // Drop any marker cargo-witness wrote before; the new one is re-emitted with
  // the key so the two never drift apart. Re-locate afterwards, since removing
  // lines shifts every index.
  const kept = st.lines.filter((l) => !l.trimStart().startsWith(EXCLUDE_MARKER));
  const at = locate(kept);

  const dotted = at.keyIndex >= 0 ? at.dotted : (at.tableIndex < 0 && at.lastDottedIndex >= 0);
  const assignment = dotted
    ? `${TABLE}.${BARE_KEY} = ${JSON.stringify(duration)}`
    : `${BARE_KEY} = ${JSON.stringify(duration)}`;
  const block = list.length ? [marker, assignment] : [assignment];

  if (at.keyIndex >= 0) {
    const indent = (kept[at.keyIndex].match(/^\s*/) || [''])[0];
    kept.splice(at.keyIndex, 1, ...block.map((l) => indent + l));
  } else if (at.tableIndex >= 0) {
    kept.splice(at.tableIndex + 1, 0, ...block);
  } else if (at.lastDottedIndex >= 0) {
    // A `[registry]` table here would be a TOML error; stay in dotted form.
    kept.splice(at.lastDottedIndex + 1, 0, ...block);
  } else {
    if (kept.length && kept[kept.length - 1].trim() !== '') kept.push('');
    kept.push(`[${TABLE}]`, ...block);
  }

  const out = kept.join(st.eol) + (st.trailingNewline ? st.eol : '');
  fs.mkdirSync(path.dirname(path.resolve(configPath)), { recursive: true });
  fs.writeFileSync(configPath, out);

  return {
    written: true,
    created: !st.exists,
    previous: st.value,
    previousExcludes: st.excludes,
    dotted,
    value: duration,
    path: configPath,
  };
}

/**
 * Installed cargo, and whether it is new enough to enforce these keys.
 * min-publish-age is stabilized for Rust 1.100 (rust-lang/cargo#17335); on
 * anything older the file is inert until the user upgrades. Never asserted —
 * always read from the toolchain that is actually installed.
 *
 * @returns {{version:string|null, major:number|null, minor:number|null,
 *   enforces:boolean|null, error:string|null}}
 */
function cargoToolchain() {
  let out;
  try {
    out = cp.execFileSync('cargo', ['--version'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10000,
    });
  } catch (e) {
    const reason = e.code === 'ENOENT' ? 'cargo not found on PATH'
      : e.code === 'ETIMEDOUT' ? 'cargo --version timed out'
        : String(e.message).split('\n')[0];
    return { version: null, major: null, minor: null, enforces: null, error: reason };
  }
  const m = String(out).match(/cargo\s+(\d+)\.(\d+)\.(\d+)/);
  if (!m) {
    return {
      version: String(out).trim(), major: null, minor: null, enforces: null,
      error: 'unrecognised cargo --version output',
    };
  }
  const major = Number(m[1]);
  const minor = Number(m[2]);
  return {
    version: `${major}.${minor}.${m[3]}`,
    major,
    minor,
    enforces: major > 1 || (major === 1 && minor >= 100),
    error: null,
  };
}

module.exports = {
  readCargoConfig, writeCargoConfig, cargoToolchain, KEY, EXCLUDE_MARKER, RESOLVER_KEY,
};
