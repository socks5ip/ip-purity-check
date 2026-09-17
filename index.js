#!/usr/bin/env node
/**
 * ip-purity-check — score an IP's "cleanliness" using DNS only.
 *
 * The idea: whether an IP gets trusted is decided less by what a website says about it
 * and more by whether the networks that watch abuse will talk about it. Those networks
 * publish their answers over DNS. So this tool asks them - directly, in parallel - and
 * turns the replies into a single score you can reason about.
 *
 *   - ~25 independent DNSBLs (Spamhaus, SpamCop, Barracuda, DroneBL, ...)
 *   - reverse DNS (PTR) presence
 *   - a 0-100 score plus a confidence level, so "no data" never looks like "clean"
 *
 * No API key. No account. No third-party HTTP service. No dependencies.
 * Everything here is a DNS query you could run yourself with `dig`.
 *
 * Usage
 *   $ ip-purity-check 1.2.3.4
 *   $ ip-purity-check 1.2.3.4 5.6.7.8 --json
 *   $ ip-purity-check 1.2.3.4 --dns 1.1.1.1
 *
 * Programmatic
 *   const { check } = require('ip-purity-check');
 *   const report = await check('1.2.3.4');
 *
 * Companion tooling: https://socks5ip.com.cn/ip-check-center/
 */
'use strict';

const dns = require('dns');
const { promises: dnsP } = dns;

/**
 * Blocklists queried, each reversed-octet style: <d>.<c>.<b>.<a>.<list>
 * `weight` is how much a single hit subtracts from 100, scaled by how widely the list is
 * consulted and how damaging a listing actually is in practice.
 */
const DNSBL_LISTS = [
  { host: 'zen.spamhaus.org', label: 'Spamhaus ZEN', weight: 25 },
  { host: 'bl.spamcop.net', label: 'SpamCop', weight: 15 },
  { host: 'b.barracudacentral.org', label: 'Barracuda', weight: 15 },
  { host: 'cbl.abuseat.org', label: 'Abusix CBL', weight: 15 },
  { host: 'dnsbl.dronebl.org', label: 'DroneBL', weight: 12 },
  { host: 'bl.blocklist.de', label: 'Blocklist.de', weight: 12 },
  { host: 'dnsbl.justspam.org', label: 'JustSpam', weight: 10 },
  { host: 'psbl.surriel.com', label: 'PSBL', weight: 10 },
  { host: 'ubl.unsubscore.com', label: 'UCEPROTECT L2', weight: 10 },
  { host: 'dnsbl-1.uceprotect.net', label: 'UCEPROTECT L1', weight: 10 },
  { host: 'dyna.spamrats.com', label: 'SpamRats Dyna', weight: 10 },
  { host: 'spam.spamrats.com', label: 'SpamRats Spam', weight: 10 },
  { host: 'tor.dan.me.uk', label: 'TOR exit nodes', weight: 10 },
  { host: 'db.wpbl.info', label: 'WPBL', weight: 8 },
  { host: 'ips.backsc.org', label: 'Backscatterer', weight: 8 },
  { host: 'noptr.spamrats.com', label: 'SpamRats NoPtr', weight: 8 },
  { host: 'spam.dnsbl.manitu.net', label: 'Manitu', weight: 8 },
  { host: 'truncate.gbudb.net', label: 'GBUdb Truncate', weight: 8 },
  { host: 'access.redhawk.org', label: 'Redhawk', weight: 8 },
  { host: 'hostkarma.junkemailfilter.com', label: 'HostKarma', weight: 8 },
  { host: 'dnsbl.tornevall.org', label: 'Tornevall', weight: 8 },
  { host: 'rbl.interserver.net', label: 'InterServer', weight: 8 },
  { host: 'spamsources.fabel.dk', label: 'SpamSources', weight: 8 },
  { host: 'all.s5h.net', label: 's5h.net', weight: 8 },
  { host: '0spam.fusionzero.com', label: 'FusionZero', weight: 6 },
];

const DEFAULTS = {
  timeoutMs: 6000,
  concurrency: 8,
  /** Missing PTR is a weak signal - plenty of legitimate IPs have none. */
  ptrPenalty: 5,
  /** Below this share of reachable lists, the score stops meaning anything. */
  minCoverage: 0.6,
};

function isIPv4(ip) {
  const parts = String(ip).trim().split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && +p <= 255);
}

function isIPv6(ip) {
  return String(ip).includes(':');
}

function reverseOctets(ip) {
  return String(ip).trim().split('.').reverse().join('.');
}

/** Race a promise against a timer so a dead resolver can never hang the whole run. */
function withTimeout(promise, ms, onTimeout) {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) { settled = true; resolve(onTimeout()); }
    }, ms);
    promise.then(
      (v) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } },
      (e) => { if (!settled) { settled = true; clearTimeout(timer); resolve({ state: 'unreachable', err: (e && e.code) || String(e) }); } }
    );
  });
}

/**
 * Ask one blocklist about one IP.
 *
 * Answer semantics (the part most people get wrong):
 *   127.0.0.x          -> listed, x identifies the reason category
 *   127.255.255.x      -> the resolver itself was refused (public DNS servers are
 *                         commonly blocked by Spamhaus etc.) - NOT a hit
 *   NXDOMAIN           -> not listed (the normal, clean answer)
 *   timeout / SERVFAIL -> unknown, must never be reported as clean
 */
async function queryList(ip, entry, timeoutMs) {
  const qname = reverseOctets(ip) + '.' + entry.host;
  const raw = await withTimeout(
    (async () => {
      try {
        const addrs = await dnsP.resolve4(qname);
        return { state: 'answer', addrs: addrs || [] };
      } catch (e) {
        const code = (e && e.code) || '';
        if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'NXDOMAIN') return { state: 'clean' };
        return { state: 'unreachable', err: code || String((e && e.message) || e) };
      }
    })(),
    timeoutMs,
    () => ({ state: 'unreachable', err: 'TIMEOUT' })
  );

  if (raw.state === 'answer') {
    const listed = raw.addrs.filter((a) => /^127\./.test(a) && !/^127\.255\.255\./.test(a));
    const refused = raw.addrs.some((a) => /^127\.255\.255\./.test(a));
    if (listed.length) return { state: 'listed', codes: listed };
    if (refused) return { state: 'unreachable', err: 'QUERY_REFUSED_BY_LIST' };
    return { state: 'clean' };
  }
  return raw;
}

/** Returns { names, ok } - `ok:false` means the lookup itself failed, which is not evidence of absence. */
async function reverseDns(ip, timeoutMs) {
  const r = await withTimeout(
    dnsP.reverse(ip)
      .then((n) => ({ state: 'answer', names: n || [] }))
      .catch((e) => ({ state: 'fail', err: (e && e.code) || '' })),
    timeoutMs,
    () => ({ state: 'fail', err: 'TIMEOUT' })
  );
  return { names: r.names || [], ok: r.state === 'answer' };
}

function grade(score) {
  if (score >= 90) return 'Clean';
  if (score >= 70) return 'Good';
  if (score >= 40) return 'Fair';
  return 'Poor';
}

/** Run an async mapper over items with a fixed concurrency ceiling. */
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let cursor = 0;
  const workers = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

/**
 * Check one IP. Returns a report object; never throws for a well-formed IPv4.
 *
 * @param {string} ip
 * @param {{timeoutMs?:number, concurrency?:number, lists?:Array, dnsServers?:string[]}} [opts]
 */
async function check(ip, opts) {
  const o = Object.assign({}, DEFAULTS, opts || {});
  const lists = (o.lists && o.lists.length ? o.lists : DNSBL_LISTS);

  if (o.dnsServers && o.dnsServers.length) {
    dns.setServers(o.dnsServers);
  }

  if (isIPv6(ip)) {
    const r = await reverseDns(ip, o.timeoutMs);
    return {
      ip,
      score: null,
      grade: 'Not scored',
      supported: false,
      reason: 'IPv6 is not scored here: DNSBL coverage for IPv6 is still thin and inconsistent, so a number would imply more confidence than the data supports.',
      ptr: r.names,
      checkedAt: new Date().toISOString(),
    };
  }
  if (!isIPv4(ip)) {
    return { ip, score: null, grade: 'Invalid', supported: false, reason: 'Not an IPv4 address.', checkedAt: new Date().toISOString() };
  }

  const [results, ptr] = await Promise.all([
    mapLimit(lists, o.concurrency, (entry) => queryList(ip, entry, o.timeoutMs)),
    reverseDns(ip, o.timeoutMs),
  ]);

  const hits = [];
  let unreachable = 0;
  results.forEach((r, i) => {
    if (r.state === 'listed') hits.push({ list: lists[i].label, host: lists[i].host, weight: lists[i].weight, codes: r.codes });
    else if (r.state === 'unreachable') unreachable++;
  });

  let score = 100;
  for (const h of hits) score -= h.weight;
  if (ptr.ok && !ptr.names.length) score -= o.ptrPenalty;
  score = Math.max(0, Math.min(100, score));

  const answered = lists.length - unreachable;
  const coverage = lists.length ? answered / lists.length : 0;
  const confidence = coverage >= 0.8 ? 'high' : coverage >= o.minCoverage ? 'medium' : 'low';

  // A score built on almost no answers is worse than no score: it looks like a clean bill
  // of health while actually meaning "we could not ask". Refuse to grade it.
  const usable = confidence !== 'low';
  return {
    ip,
    score: usable ? score : null,
    rawScore: score,
    grade: usable ? grade(score) : 'Inconclusive',
    confidence,
    supported: true,
    checked: lists.length,
    answered,
    coverage: Math.round(coverage * 100) / 100,
    listed: hits.length,
    unreachable,
    hits,
    ptr: ptr.names,
    ptrChecked: ptr.ok,
    checkedAt: new Date().toISOString(),
  };
}

function render(report) {
  const line = '-'.repeat(60);
  const out = [];
  out.push('IP Purity Report  ' + report.ip);
  out.push(line);

  if (!report.supported) {
    out.push('  Not scored: ' + (report.reason || 'unsupported address'));
    if (report.ptr && report.ptr.length) out.push('  rDNS: ' + report.ptr[0]);
    out.push(line);
    out.push('  More detail: https://socks5ip.com.cn/ip-check-center/');
    return out.join('\n');
  }

  const scoreCell = report.score === null ? '  n/a' : String(report.score).padStart(4);
  out.push('  Score       ' + scoreCell + ' / 100   ' + report.grade);
  out.push('  Blacklists  ' + report.listed + ' hit / ' + report.checked + ' checked   (' +
           report.answered + ' answered, confidence ' + report.confidence + ')');
  out.push('  rDNS        ' + (report.ptrChecked ? (report.ptr.length ? report.ptr.length + ' PTR' : 'none') : 'lookup failed'));

  if (report.hits.length) {
    out.push('');
    out.push('  Listed on:');
    for (const h of report.hits) out.push('    x ' + String(h.list).padEnd(22) + ' ' + h.codes.join(', '));
  }
  if (report.ptr.length) {
    out.push('');
    out.push('  rDNS:');
    for (const n of report.ptr.slice(0, 5)) out.push('    ' + n);
  }

  out.push('');
  if (!report.ptrChecked) {
    out.push('  Note: the reverse-DNS lookup failed, so it was not counted against the score.');
  }
  if (report.grade === 'Inconclusive') {
    out.push('  Not scored: only ' + report.answered + ' of ' + report.checked +
             ' lists answered from this resolver.');
    out.push('  An unreachable list is not a clean list. Point the tool at a resolver the');
    out.push('  blocklists accept (--dns 1.1.1.1) and run it again.');
  } else if (report.unreachable) {
    out.push('  Note: ' + report.unreachable + ' list(s) did not answer. Unreachable != clean,');
    out.push('  and it does not count against the score.');
  }
  out.push(line);
  out.push('  Score = 100 minus blocklist weights; a missing PTR costs a few points.');
  out.push('  More detail: https://socks5ip.com.cn/ip-check-center/');
  return out.join('\n');
}

function usage() {
  return [
    "ip-purity-check - score an IP's cleanliness using DNS only (no API key, no deps)",
    '',
    'Usage:',
    '  ip-purity-check <ip> [<ip> ...] [options]',
    '',
    'Options:',
    '  --json               Machine-readable output',
    '  --dns <s1[,s2]>      Resolver(s) to query, e.g. --dns 1.1.1.1',
    '  --timeout <ms>       Per-query timeout (default 6000)',
    '  --concurrency <n>    Parallel queries (default 8)',
    '  --list               Print the blocklists queried and exit',
    '  -h, --help           This message',
    '',
    'Examples:',
    '  ip-purity-check 1.2.3.4',
    '  ip-purity-check 1.2.3.4 5.6.7.8 --json',
    '  ip-purity-check 1.2.3.4 --dns 1.1.1.1',
    '',
    'Docs: https://socks5ip.com.cn/ip-check-center/',
  ].join('\n');
}

async function main(argv) {
  const args = argv.slice(2);
  if (!args.length || args.includes('-h') || args.includes('--help')) {
    console.log(usage());
    return 0;
  }
  if (args.includes('--list')) {
    console.log(DNSBL_LISTS.length + ' blocklists queried:');
    for (const l of DNSBL_LISTS) console.log('  ' + String(l.label).padEnd(20) + String(l.host).padEnd(32) + '- weight ' + l.weight);
    return 0;
  }

  const opts = {};
  const ips = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') opts.json = true;
    else if (a === '--dns') opts.dnsServers = String(args[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--timeout') opts.timeoutMs = parseInt(args[++i], 10) || DEFAULTS.timeoutMs;
    else if (a === '--concurrency') opts.concurrency = Math.max(1, Math.min(32, parseInt(args[++i], 10) || DEFAULTS.concurrency));
    else if (a.startsWith('-')) { console.error('Unknown option: ' + a); return 2; }
    else ips.push(a);
  }
  if (!ips.length) { console.log(usage()); return 0; }

  const reports = [];
  for (const ip of ips) reports.push(await check(ip, opts));

  if (opts.json) {
    console.log(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2));
  } else {
    console.log(reports.map(render).join('\n\n'));
  }
  // Exit code hints at the outcome: 0 clean, 1 listed, 2 could not be scored.
  if (reports.some((r) => r.supported === false || r.grade === 'Inconclusive')) return 2;
  if (reports.some((r) => r.listed > 0)) return 1;
  return 0;
}

module.exports = { check, render, DNSBL_LISTS, DEFAULTS };

if (require.main === module) {
  main(process.argv)
    .then((code) => process.exit(code))
    .catch((e) => { console.error('ip-purity-check: ' + ((e && e.stack) || e)); process.exit(3); });
}
