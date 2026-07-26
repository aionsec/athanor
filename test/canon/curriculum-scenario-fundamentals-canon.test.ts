// Canon-contract drift guard for the sample dataset. Asserts that the pipeline's own
// output satisfies the scenario's RELATIONSHIPS and STRUCTURE — that the candidates still
// describe the intrusion `fixtures/README.md` describes.
//
// The subject is athanor's OWN pipeline output over `fixtures/events.json`, not the golden
// file read off disk. Pins A and B already prove those are byte-equal, so reading the
// golden here would assert nothing this repo can break.
//
// Pipeline output IS canon: absolute scores are NOT pinned (they get swept into
// lessons later and would make this test brittle). Only structural invariants
// and score ORDERINGS are asserted, plus the two hard thresholds the taught
// discriminators rely on (PSI encoded-command signal; DT exfil volume band).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { repoRoot } from '../../src/lib/paths.js';
import { runPipeline } from '../../src/run/runner.js';
import type { TelemetryEvent } from '../../src/schema/events.js';

type Candidate = Record<string, unknown>;

// A downstream consumer's invocation gate, pinned here as a contract test.
//
// Automated analysis layers built on top of a distillation pipeline decide what to look at
// by testing candidate fields — "run the C2-over-HTTPS analysis when the beacon's
// observed_service is ssl". That makes `observed_service` load-bearing OUTSIDE this repo:
// resolve it to null and the candidate silently stops being eligible, with nothing in
// athanor failing. This gate is a stand-in for that class of consumer, so the field's
// resolution stays pinned rather than incidental.
const C2_OVER_HTTPS_BOUNDARY = {
  skillName: 'hunt-c2-over-https',
  candidateType: 'beacon',
  documentedInvocationGate: "candidate.observed_service == 'ssl'",
  gate: (candidate: Candidate): boolean => {
    const value = candidate.observed_service;
    const asString = typeof value === 'string' && value.trim() ? value.trim() : undefined;
    return asString?.toLowerCase() === 'ssl';
  },
} as const;

const FIXTURES = join(repoRoot(), 'fixtures');

function loadEventsFixture(name: string): TelemetryEvent[] {
  const parsed = JSON.parse(readFileSync(join(FIXTURES, name), 'utf-8')) as unknown;
  assert.ok(Array.isArray(parsed), `${name} must be a JSON array`);
  return parsed as TelemetryEvent[];
}

// Athanor's own pipeline output is the subject under test — not the golden file.
const run = runPipeline(loadEventsFixture('events.json'));
const candidates = run.candidates as unknown as Candidate[];
const events = run.events as unknown as Candidate[];

function byType(type: string): Candidate[] {
  return candidates.filter((c) => c.type === type);
}

function num(value: unknown): number {
  assert.equal(typeof value, 'number', `expected a number, got ${JSON.stringify(value)}`);
  return value as number;
}

function beaconByDest(destIp: string): Candidate {
  const matches = byType('beacon').filter((c) => c.dest_ip === destIp);
  assert.equal(matches.length, 1, `expected exactly one beacon to ${destIp}, found ${matches.length}`);
  return matches[0];
}

function primaryScore(c: Candidate): number {
  const field = `${String(c.type)}_score`;
  return num(c[field]);
}

describe('curriculum-scenario-fundamentals canon contract', () => {
  // 1. Exactly the five taught candidate types; zero of the excluded types.
  it('contains exactly the five taught candidate types', () => {
    const present = new Set(candidates.map((c) => String(c.type)));
    const expected = new Set([
      'beacon',
      'data_transfer',
      'tls_anomaly',
      'unusual_parent_child_anomaly',
      'powershell_invocation_anomaly',
    ]);
    assert.deepEqual(
      [...present].sort(),
      [...expected].sort(),
      `candidate types present: ${[...present].sort().join(', ')}`,
    );
    for (const excluded of [
      'intel_match',
      'credential_access',
      'remote_interactive_logon_anomaly',
      'rdp_session_anomaly',
    ]) {
      assert.equal(byType(excluded).length, 0, `expected zero ${excluded} candidates`);
    }
  });

  // 1b. Pin the EXACT per-type counts (and the total). The presentation-id check
  //     below derives its expected ids from group.length, so it is self-fulfilling
  //     on count — a 6th mid-band beacon or a 2nd PSI would renumber silently and
  //     still pass. These pins are the real count guard. (DT and TLS also pinned in
  //     their own tests below.)
  it('pins the exact per-type candidate counts', () => {
    assert.equal(candidates.length, 10, `expected 10 total candidates, found ${candidates.length}`);
    assert.equal(byType('beacon').length, 5, 'expected exactly 5 beacon candidates');
    assert.equal(byType('data_transfer').length, 1, 'expected exactly 1 data_transfer candidate');
    assert.equal(byType('tls_anomaly').length, 1, 'expected exactly 1 tls_anomaly candidate');
    assert.equal(byType('unusual_parent_child_anomaly').length, 2, 'expected exactly 2 UPCA candidates');
    assert.equal(byType('powershell_invocation_anomaly').length, 1, 'expected exactly 1 PSI candidate');
  });

  // 2. Presentation ids: sequential <PREFIX>-001..N per type with the right prefix,
  //    and every candidate carries a pipeline_candidate_id hash id.
  it('assigns rank-ordered presentation ids and preserves the pipeline hash id', () => {
    const prefixByType: Record<string, string> = {
      beacon: 'BCN',
      data_transfer: 'DT',
      tls_anomaly: 'TLS',
      unusual_parent_child_anomaly: 'UPCA',
      powershell_invocation_anomaly: 'PSI',
    };
    for (const [type, prefix] of Object.entries(prefixByType)) {
      const group = byType(type);
      assert.ok(group.length >= 1, `expected >= 1 ${type} candidate`);
      const ids = group.map((c) => String(c.candidate_id)).sort();
      const expected = group
        .map((_, i) => `${prefix}-${String(i + 1).padStart(3, '0')}`)
        .sort();
      assert.deepEqual(ids, expected, `${type} presentation ids: ${ids.join(', ')}`);
    }
    for (const c of candidates) {
      assert.match(
        String(c.pipeline_candidate_id),
        /^[A-Z]{3}-[0-9a-f]{16}$/,
        `pipeline_candidate_id malformed: ${JSON.stringify(c.pipeline_candidate_id)}`,
      );
    }
  });

  // 3. Beacon relationships (by dest_ip).
  it('orders the five beacons: DT-channel C2, benign heartbeat decoy, ambiguous, two low benigns', () => {
    const heartbeat = beaconByDest('104.18.22.51');
    const c2 = beaconByDest('193.42.33.81');
    const ambiguous = beaconByDest('91.213.50.77');
    const outlook = beaconByDest('52.96.0.1');
    const azure = beaconByDest('20.60.181.10');

    const s = (c: Candidate) => num(c.beacon_score);
    const allBeaconScores = byType('beacon').map(s);
    const maxScore = Math.max(...allBeaconScores);

    // heartbeat is the highest beacon AND strictly above the C2 beacon
    assert.equal(s(heartbeat), maxScore, 'heartbeat must be the max beacon_score');
    assert.ok(s(heartbeat) > s(c2), `heartbeat (${s(heartbeat)}) must exceed C2 (${s(c2)})`);

    // Pin BCN-001 directly to the max-score beacon (not only transitively via the
    // rank-ordered presentation-id assignment): the top-ranked beacon id must be
    // the heartbeat/max.
    const topBeaconById = [...byType('beacon')].sort((a, b) =>
      String(a.candidate_id).localeCompare(String(b.candidate_id)))[0];
    assert.equal(String(topBeaconById.candidate_id), 'BCN-001', 'first beacon id must be BCN-001');
    assert.equal(s(topBeaconById), maxScore, 'BCN-001 must be the max-score beacon');
    assert.equal(topBeaconById.dest_ip, '104.18.22.51', 'BCN-001 must be the heartbeat destination');

    // C2 beacon in [0.75, 0.92]
    assert.ok(s(c2) >= 0.75 && s(c2) <= 0.92, `C2 beacon_score ${s(c2)} out of [0.75, 0.92]`);

    // ambiguous strictly between the two low benigns and the C2
    assert.ok(s(ambiguous) > s(outlook), `ambiguous (${s(ambiguous)}) must exceed Outlook (${s(outlook)})`);
    assert.ok(s(ambiguous) > s(azure), `ambiguous (${s(ambiguous)}) must exceed AzureBackup (${s(azure)})`);
    assert.ok(s(ambiguous) < s(c2), `ambiguous (${s(ambiguous)}) must be below C2 (${s(c2)})`);

    // Outlook and AzureBackup are the two lowest beacons
    const sorted = [...allBeaconScores].sort((a, b) => a - b);
    const twoLowest = new Set(sorted.slice(0, 2));
    // Guard the "two lowest" claim against ties spilling past index 1.
    assert.ok(s(outlook) <= sorted[1], `Outlook (${s(outlook)}) must be among the two lowest`);
    assert.ok(s(azure) <= sorted[1], `AzureBackup (${s(azure)}) must be among the two lowest`);
    assert.ok(twoLowest.has(s(outlook)) && twoLowest.has(s(azure)),
      'Outlook and AzureBackup must be the two lowest beacon scores');
  });

  // 4. DT: exactly one, on the C2 tuple, ~850 MB, and its score is the max primary
  //    score across ALL candidates.
  it('has one data_transfer on the C2 tuple with the top primary score', () => {
    const dts = byType('data_transfer');
    assert.equal(dts.length, 1, `expected exactly one data_transfer, found ${dts.length}`);
    const dt = dts[0];
    assert.equal(dt.dest_ip, '193.42.33.81', 'DT dest_ip must be the C2');
    assert.equal(num(dt.dest_port), 443, 'DT dest_port must be 443');

    // same src|dest|port tuple as the C2 beacon
    const c2 = beaconByDest('193.42.33.81');
    assert.equal(dt.src_ip, c2.src_ip, 'DT and C2 beacon must share src_ip');
    assert.equal(dt.dest_ip, c2.dest_ip, 'DT and C2 beacon must share dest_ip');
    assert.equal(dt.dest_port, c2.dest_port, 'DT and C2 beacon must share dest_port');

    const bytesOut = num(dt.bytes_out_total);
    assert.ok(bytesOut >= 800e6 && bytesOut <= 900e6, `DT bytes_out_total ${bytesOut} out of [800e6, 900e6]`);

    const dtScore = num(dt.data_transfer_score);
    for (const c of candidates) {
      assert.ok(
        dtScore >= primaryScore(c),
        `DT score ${dtScore} must be >= ${String(c.type)} score ${primaryScore(c)} (${String(c.candidate_id)})`,
      );
    }
  });

  // 5. TLS: exactly one tls_anomaly on the C2 tuple.
  it('has one tls_anomaly on the C2 tuple', () => {
    const tls = byType('tls_anomaly');
    assert.equal(tls.length, 1, `expected exactly one tls_anomaly, found ${tls.length}`);
    assert.equal(tls[0].dest_ip, '193.42.33.81', 'TLS dest_ip must be the C2');
    assert.equal(num(tls[0].dest_port), 443, 'TLS dest_port must be 443');
  });

  // 6. UPCA: node.exe->powershell.exe (taxonomy) AND powershell.exe->node-bridge.exe
  //    (npm-cache path rule), both at 0.85.
  it('has both supply-chain UPCA pairs at 0.85', () => {
    const upca = byType('unusual_parent_child_anomaly');
    const nodeToPs = upca.find(
      (c) => String(c.parent_process_name).toLowerCase() === 'node.exe'
        && String(c.process_name).toLowerCase() === 'powershell.exe',
    );
    const psToBridge = upca.find(
      (c) => String(c.parent_process_name).toLowerCase() === 'powershell.exe'
        && String(c.process_name).toLowerCase() === 'node-bridge.exe',
    );
    assert.ok(nodeToPs, 'expected a node.exe -> powershell.exe UPCA candidate');
    assert.ok(psToBridge, 'expected a powershell.exe -> node-bridge.exe UPCA candidate');
    assert.equal(num(nodeToPs!.unusual_parent_child_anomaly_score), 0.85, 'node->ps score must be 0.85');
    assert.equal(num(psToBridge!.unusual_parent_child_anomaly_score), 0.85, 'ps->node-bridge score must be 0.85');
  });

  // 6b. Spawn-signature aggregation: the ps->node-bridge spawn is observed by THREE
  //     eid1 events (the UPCA stage's true spawn + the beacon-C2 and DT attribution
  //     sightings of the same implant identity) which the UPCA distiller collapses
  //     into ONE candidate whose evidence carries all three — the aggregation is why
  //     the identity-coherent dataset still has exactly 2 UPCA candidates. The
  //     candidate's PRIMARY must be the earliest observation — the true spawn — so
  //     its command_line stays the real implant invocation, never the beacon
  //     sighting's enrichment-templated one. No literal event ids: regen renumbers.
  it('aggregates the three implant eid1 sightings into one ps->node-bridge candidate', () => {
    const IMPLANT_PATH = 'C:\\Users\\priya.nair\\AppData\\Local\\npm-cache\\_tmp\\node-bridge.exe';
    const psToBridge = byType('unusual_parent_child_anomaly').find(
      (c) => String(c.parent_process_name).toLowerCase() === 'powershell.exe'
        && String(c.process_name).toLowerCase() === 'node-bridge.exe',
    );
    assert.ok(psToBridge, 'expected a powershell.exe -> node-bridge.exe UPCA candidate');
    const evidence = psToBridge!.evidence as Record<string, unknown> | undefined;
    assert.ok(evidence, 'ps->node-bridge candidate must carry evidence');
    const ids = evidence!.constituent_event_ids;
    assert.ok(Array.isArray(ids), 'evidence.constituent_event_ids must be an array');
    assert.equal(ids.length, 3, `expected exactly 3 constituent events, found ${ids.length}`);

    const byId = new Map(events.map((e) => [String(e.id), e]));
    const resolved = (ids as unknown[]).map((id) => {
      const e = byId.get(String(id));
      assert.ok(e, `constituent event ${String(id)} must exist in events_enriched.json`);
      assert.equal(num0(e!.event_id), 1, `constituent event ${String(id)} must be a sysmon eid1`);
      assert.equal(e!.process_name, 'node-bridge.exe', `constituent event ${String(id)} must be a node-bridge.exe spawn`);
      assert.equal(e!.process_path, IMPLANT_PATH, `constituent event ${String(id)} must carry the npm-cache implant path`);
      return e!;
    });

    // Chronological + three DISTINCT observations (strictly increasing timestamps:
    // the true spawn, then the beacon-stage sighting, then the DT-stage sighting).
    const times = resolved.map((e) => Date.parse(String(e.timestamp)));
    for (const [i, t] of times.entries()) {
      assert.ok(Number.isFinite(t), `constituent event ${String(resolved[i].id)} must carry a parseable timestamp`);
      if (i > 0) {
        assert.ok(t > times[i - 1],
          `constituent events must be strictly chronological: ${String(resolved[i - 1].id)} -> ${String(resolved[i].id)}`);
      }
    }

    // Primary = the earliest observation (the true spawn): the candidate's window
    // and process identity must be the first constituent event's, verbatim.
    assert.equal(psToBridge!.time_window_start, resolved[0].timestamp,
      'ps->node-bridge window must start at the true spawn (earliest observation is primary)');
    assert.equal(psToBridge!.process_guid, resolved[0].process_guid,
      'ps->node-bridge primary identity must be the true spawn process');
    assert.equal(psToBridge!.command_line, IMPLANT_PATH,
      'ps->node-bridge command_line must be the real implant invocation, not an enrichment-templated line');
  });

  // 7. PSI: the encoded loader — score >= 0.9, a high non-null encoded-command
  //    entropy, and cmdline_length >= 400.
  //
  // NOTE ON ENTROPY: the plan's draft named ">5". A real PowerShell
  // `-EncodedCommand` value is base64(UTF-16LE(script)); UTF-16LE inserts a null
  // byte per ASCII char, so its base64 Shannon entropy is STRUCTURALLY capped
  // around ~4.3 (only base64 of raw random bytes reaches ~5.9, which is not a
  // valid encoded command). The pipeline's own value here is ~4.27 — that IS the
  // canon. We assert a high, non-null entropy (> 4.0) that cleanly separates the
  // encoded loader from benign/short-encoded PSI (null / <4). See task-6 report.
  it('has an encoded-command PSI loader (score >= 0.9, high entropy, long cmdline)', () => {
    const loaders = byType('powershell_invocation_anomaly').filter((c) => {
      const entropy = c.encoded_command_entropy;
      return num(c.powershell_invocation_anomaly_score) >= 0.9
        && typeof entropy === 'number'
        && entropy > 4.0
        && num(c.cmdline_length) >= 400;
    });
    assert.ok(loaders.length >= 1, 'expected >= 1 encoded-command PSI loader');
  });

  // 8. Events: no lateral/credential/RDP telemetry; window-bounded; fleet present.
  it('events are intel-dark, movement-free, window-bounded, with the fleet present', () => {
    const start = Date.parse('2026-03-09T12:00:00Z');
    const end = Date.parse('2026-03-09T20:00:00Z');
    const hosts = new Set<string>();
    for (const e of events) {
      // no RDP destination port
      assert.notEqual(num0(e.dest_port), 3389, `unexpected port 3389 event: ${String(e.id)}`);
      // no 4624 Type-10 interactive logons
      const isType10Logon =
        (e.event_id === 4624 || e.event_id === '4624') &&
        (e.logon_type === 10 || e.logon_type === '10');
      assert.ok(!isType10Logon, `unexpected 4624 Type-10 logon: ${String(e.id)}`);
      // no lsass / sysmon eid10 process-access
      assert.notEqual(num0(e.event_id), 10, `unexpected sysmon eid10 event: ${String(e.id)}`);
      assert.ok(
        String(e.event_type ?? '') !== 'process_access',
        `unexpected process_access event: ${String(e.id)}`,
      );
      if (typeof e.target_image === 'string') {
        assert.ok(!e.target_image.toLowerCase().includes('lsass'), `unexpected lsass access: ${String(e.id)}`);
      }
      // timestamps within the window
      const ts = Date.parse(String(e.timestamp));
      assert.ok(Number.isFinite(ts) && ts >= start && ts <= end, `timestamp out of window: ${String(e.timestamp)}`);
      const host = e.host;
      if (typeof host === 'string' && host.length > 0) hosts.add(host);
    }
    assert.ok(hosts.size >= 20, `expected >= 20 distinct hosts (fleet), found ${hosts.size}`);
  });

  // 9. C2 rarity: very_rare band — a large population, a single connecting host.
  it('shows the C2 destination as very_rare (host_count 1 in a >=20-host population)', () => {
    const c2 = beaconByDest('193.42.33.81');
    const enrichment = c2.enrichment as Record<string, unknown> | undefined;
    assert.ok(enrichment, 'C2 beacon must carry enrichment');
    const freq = enrichment!.destination_frequency as Record<string, unknown> | undefined;
    assert.ok(freq, 'C2 beacon must carry enrichment.destination_frequency');
    assert.ok(num(freq!.population_host_count) >= 20, `population_host_count ${JSON.stringify(freq!.population_host_count)} must be >= 20`);
    assert.equal(num(freq!.host_count), 1, 'C2 host_count must be 1');
    assert.equal(freq!.rarity_bucket, 'very_rare', `C2 rarity_bucket must be very_rare, got ${JSON.stringify(freq!.rarity_bucket)}`);
  });

  // 10. Identity coherence: the C2 beacon (BCN-002) and the exfil (DT-001) are the
  //     SAME implant — node-bridge.exe from the npm cache, run by priya.nair, spawned
  //     by powershell.exe — matching the UPCA ps->node-bridge child identity, so the
  //     implant has ONE coherent identity across all DEVBOX-07 stages.
  it('attributes the C2 beacon and the exfil to the coherent npm-cache implant identity', () => {
    const IMPLANT_PATH = 'C:\\Users\\priya.nair\\AppData\\Local\\npm-cache\\_tmp\\node-bridge.exe';
    const c2Eid3 = events.filter((e) => num0(e.event_id) === 3 && e.dest_ip === '193.42.33.81');
    assert.ok(c2Eid3.length > 0, 'expected sysmon eid3 events on the C2 tuple');
    for (const e of c2Eid3) {
      assert.equal(e.user, 'LARKSPUR\\priya.nair', `C2/exfil eid3 user must be LARKSPUR\\priya.nair: ${String(e.id)}`);
    }
    const guids = new Set(c2Eid3.map((e) => String(e.process_guid)));
    const c2Eid1 = events.filter((e) => num0(e.event_id) === 1 && guids.has(String(e.process_guid)));
    assert.ok(c2Eid1.length > 0, 'expected sysmon eid1 events for the C2/exfil implant process');
    for (const e of c2Eid1) {
      assert.equal(e.process_path, IMPLANT_PATH, `C2/exfil eid1 process_path must be the npm-cache implant: ${String(e.id)}`);
      assert.equal(e.user, 'LARKSPUR\\priya.nair', `C2/exfil eid1 user must be LARKSPUR\\priya.nair: ${String(e.id)}`);
      assert.equal(e.parent_process_name, 'powershell.exe', `C2/exfil eid1 parent must be powershell.exe: ${String(e.id)}`);
    }

    // Candidate-level payoff of the coherent identity: the C2 tuple maps to exactly
    // ONE implant process, so both candidates attribute at FULL confidence with no
    // data-quality flags (before the convergence they were partial_multi_process
    // with a multi_process_match flag). A second process on the tuple would silently
    // downgrade both — this is the guard.
    const dt = byType('data_transfer')[0];
    assert.ok(dt, 'expected a data_transfer candidate');
    for (const [label, c] of [
      ['BCN-002 (C2 beacon)', beaconByDest('193.42.33.81')],
      ['DT-001 (exfil)', dt],
    ] as Array<[string, Candidate]>) {
      const attribution = c.attribution as Record<string, unknown> | undefined;
      assert.ok(attribution, `${label} must carry attribution`);
      assert.equal(attribution!.confidence, 'full', `${label} attribution.confidence must be "full"`);
      assert.deepEqual(attribution!.data_quality_flags, [], `${label} attribution.data_quality_flags must be empty`);
    }
  });

  // 10b. No event anywhere may carry the data-transfer generator's fallback
  //      identity string DOMAIN\user — a foreign-domain leak in a LARKSPUR dataset.
  it('contains no generator-fallback DOMAIN\\user identity anywhere in the events', () => {
    const hasNeedle = (v: unknown): boolean => {
      if (typeof v === 'string') return v.includes('DOMAIN\\user');
      if (v && typeof v === 'object') return Object.values(v).some(hasNeedle);
      return false;
    };
    for (const e of events) {
      assert.ok(!hasNeedle(e), `event carries the DOMAIN\\user fallback identity: ${String(e.id)}`);
    }
  });

  // 11. RATIFY A — BCN-003's svchost.exe / NT AUTHORITY\SYSTEM attribution is
  //     DELIBERATE: a plausible system process is exactly what makes the ambiguous
  //     beacon inconclusive. Keep the default identity — do NOT suppress attribution,
  //     and do NOT thread a named user (that would resolve the ambiguity).
  it('keeps the ambiguous beacon attributed to svchost.exe under NT AUTHORITY\\SYSTEM', () => {
    const ambEid3 = events.filter((e) => num0(e.event_id) === 3 && e.dest_ip === '91.213.50.77');
    assert.ok(ambEid3.length > 0, 'expected sysmon eid3 events on the ambiguous tuple');
    for (const e of ambEid3) {
      assert.equal(e.process_name, 'svchost.exe', `ambiguous eid3 process must be svchost.exe: ${String(e.id)}`);
      assert.equal(e.user, 'NT AUTHORITY\\SYSTEM', `ambiguous eid3 user must be NT AUTHORITY\\SYSTEM: ${String(e.id)}`);
    }
    const guids = new Set(ambEid3.map((e) => String(e.process_guid)));
    const ambEid1 = events.filter((e) => num0(e.event_id) === 1 && guids.has(String(e.process_guid)));
    assert.ok(ambEid1.length > 0, 'expected a sysmon eid1 event for the ambiguous beacon process');
    for (const e of ambEid1) {
      assert.equal(e.process_name, 'svchost.exe', `ambiguous eid1 process must be svchost.exe: ${String(e.id)}`);
      assert.equal(e.user, 'NT AUTHORITY\\SYSTEM', `ambiguous eid1 user must be NT AUTHORITY\\SYSTEM: ${String(e.id)}`);
    }
  });

  // 12. Kill-chain causality: loader -> implant spawn -> first C2 connection must be
  //     strictly ordered in time. The node.exe -> encoded-powershell loader event is
  //     SHARED by UPCA-001 and PSI-001 (same eid1), so their windows coincide; the
  //     implant spawn (UPCA-002, the aggregation primary) follows the loader; the
  //     C2 beacon window opens after the spawn.
  it('orders the kill chain: loader before implant spawn before first C2 beacon', () => {
    const upca = byType('unusual_parent_child_anomaly');
    const nodeToPs = upca.find(
      (c) => String(c.parent_process_name).toLowerCase() === 'node.exe'
        && String(c.process_name).toLowerCase() === 'powershell.exe',
    );
    const psToBridge = upca.find(
      (c) => String(c.parent_process_name).toLowerCase() === 'powershell.exe'
        && String(c.process_name).toLowerCase() === 'node-bridge.exe',
    );
    assert.ok(nodeToPs, 'expected a node.exe -> powershell.exe UPCA candidate');
    assert.ok(psToBridge, 'expected a powershell.exe -> node-bridge.exe UPCA candidate');
    const psi = byType('powershell_invocation_anomaly')[0];
    assert.ok(psi, 'expected a powershell_invocation_anomaly candidate');
    const c2 = beaconByDest('193.42.33.81');

    const t = (c: Candidate, label: string): number => {
      const ms = Date.parse(String(c.time_window_start));
      assert.ok(Number.isFinite(ms), `${label} time_window_start must be a parseable timestamp`);
      return ms;
    };

    assert.equal(String(nodeToPs!.time_window_start), String(psi.time_window_start),
      'UPCA-001 and PSI-001 must share the loader event window start');
    assert.ok(t(nodeToPs!, 'loader') < t(psToBridge!, 'spawn'),
      `loader (${String(nodeToPs!.time_window_start)}) must precede the implant spawn (${String(psToBridge!.time_window_start)})`);
    assert.ok(t(psToBridge!, 'spawn') < t(c2, 'C2 beacon'),
      `implant spawn (${String(psToBridge!.time_window_start)}) must precede the first C2 connection (${String(c2.time_window_start)})`);
  });

  // 13. SSL gate: the exfil is tunnelled inside the C2's TLS session (T1041 "over the
  //     C2 channel"), so every conn on the C2 tuple carries service ssl and BCN-002's
  //     observed_service resolves to 'ssl' under the beacon scorer's unanimity rule.
  //     That is exactly what the hunt-c2-over-https invocation gate keys on
  //     (candidate.observed_service == 'ssl'). This is the regression that would have
  //     caught the whole ssl-gate class. Because the tuple is uniformly TLS, there is
  //     no http-on-443 anomaly, so DT-001.enrichment.protocol_mismatch is false — the
  //     honest value for a TLS-tunnelled transfer (pinned so the flip stays intentional).
  it('resolves BCN-002 observed_service ssl, passes the c2-over-https gate, DT protocol_mismatch false', () => {
    const c2 = beaconByDest('193.42.33.81');
    assert.equal(c2.observed_service, 'ssl',
      `C2 beacon observed_service must resolve to ssl (uniform TLS-tunnelled tuple), got ${JSON.stringify(c2.observed_service)}`);

    // The downstream invocation gate pinned at the top of this file: a consumer that
    // selects work by reading `observed_service` must still select this candidate.
    const boundary = C2_OVER_HTTPS_BOUNDARY;
    assert.equal(boundary.documentedInvocationGate, "candidate.observed_service == 'ssl'",
      'the pinned hunt-c2-over-https gate must still read on observed_service');
    assert.equal(boundary.gate(c2), true, 'BCN-002 must pass the hunt-c2-over-https invocation gate');

    const dt = byType('data_transfer')[0];
    assert.ok(dt, 'expected a data_transfer candidate');
    const enrichment = dt.enrichment as Record<string, unknown> | undefined;
    assert.ok(enrichment, 'DT-001 must carry enrichment');
    assert.equal(enrichment!.protocol_mismatch, false,
      'DT-001 protocol_mismatch must be false: TLS-tunnelled exfil over 443 is not a protocol mismatch');
  });
});

// Lenient numeric coercion for optional event fields (absent -> NaN, never throws).
function num0(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && value.trim() !== '') return Number(value);
  return NaN;
}
