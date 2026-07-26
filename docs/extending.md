# Writing a converter for your format

athanor reads five raw dialects and one normalized format. Your logs are almost certainly
not among them. This document is about closing that gap — and the gap is smaller than it
looks, because everything downstream of ingest reads
[normalized events](schema.md), not log lines. Get your data into that shape and the
whole pipeline works on it.

There are three routes, in increasing order of effort:

1. **Reshape your export into a dialect athanor already reads.** A `jq` filter, sometimes
   a one-liner. Best when your logs *are* Zeek or Sysmon and something in the shipping
   chain rearranged them.
2. **Emit a normalized `events.json`.** Write a script in any language that produces an
   array of normalized events. No athanor code involved at all.
3. **Add a dialect parser.** A new file in `src/ingest/`, about 40 lines, wired into the
   folder scan at four points.

Start at 1, fall back to 3.

---

## "This is a NUMBER written as a string"

If athanor sent you here with that message, this is the section you want.

```
conn.log:1: expected numeric zeek "ts" (epoch seconds), got "1773057630" — this is a
NUMBER written as a string, which usually means the whole export quotes every field;
athanor wants JSON numbers here. See docs/extending.md for writing a converter.
```

Some log shippers render every field as a string, so `"ts": 1773057630.0` arrives as
`"ts": "1773057630"`. athanor refuses it rather than coercing, because silent coercion
across a whole export is how a `cert_serial` of `"01"` quietly becomes the number `1`.

Fix it in the export if you can. If you cannot, name the numeric fields explicitly and
convert only those:

```bash
jq -c '["ts","id.orig_p","id.resp_p","duration","orig_bytes","resp_bytes",
        "orig_pkts","resp_pkts"] as $n
       | with_entries(if (.key | IN($n[])) and (.value | type == "string")
                      then .value |= tonumber else . end)' \
   conn.log > conn.fixed.log
```

For Sysmon EID 1 and EID 3 the numeric fields are `EventID`, `ProcessId`,
`ParentProcessId`, `SourcePort` and `DestinationPort`.

Resist the temptation to convert every numeric-looking string. Identifiers, certificate
serials, port strings in text fields and zero-padded values all look numeric and are not.
The field lists in [schema.md](schema.md) tell you which fields the pipeline reads as
numbers; those are the only ones that need converting.

## Route 2: emit a normalized `events.json`

The lowest-friction route for a format that looks nothing like Zeek or Sysmon. Write an
array of normalized event objects to `events.json`, put it alone in a folder, and point
athanor at the folder:

```bash
your-converter.py raw-export.csv > telemetry/events.json
npx @aionsec/athanor ./telemetry/
```

```
athanor: 3859 events from 1 file in ./telemetry
  events.json  normalized-events    3859
  (normalized lane: event ids were read from the file, not reconstructed)
candidates: 10
  beacon                            5
  data_transfer                     1
  tls_anomaly                       1
  unusual_parent_child_anomaly      2
  powershell_invocation_anomaly     1   (3 below the 0.6 floor)
caput mortuum (dropped by the emit floors): 3
wrote /…/candidates.json
```

Three rules govern this lane:

- **Your ids are trusted as written.** Nothing is re-derived. Assign them yourself, in
  timestamp order, and keep them stable across runs.
- **It must be the only telemetry file in the folder.** Mixing normalized events with raw
  dialect files is an error: one lane trusts the ids in the file and the other
  reconstructs them, and two id schemes in one stream would collide.
- **Non-conforming records are dropped, not refused.** The loader reports how many and at
  which array indices; watch for that warning on the first run.

The required fields per event type are in [schema.md](schema.md). Get `timestamp`,
`source`, `event_type` and the per-type required set right and the rest is optional.

## Route 3: anatomy of a parser

The Zeek `conn.log` parser is the whole pattern in 40 lines. Here it is
([`src/ingest/zeek-conn.ts`](../src/ingest/zeek-conn.ts)), with the parts that generalize
called out.

```ts
export const ZEEK_CONN_DIALECT = 'zeek/conn';

export function parseZeekConnRecord(raw: RawRecord): ParsedEvent {
  const reader = new RecordReader(raw);
  const timestampMs = reader.zeekTimestampMs();

  const origBytes = reader.optionalNumber('orig_bytes');
  const respBytes = reader.optionalNumber('resp_bytes');

  const event = compact({
    timestamp: isoFromMs(timestampMs),
    source: 'zeek',
    event_type: 'conn',
    src_ip: reader.requiredString('id.orig_h'),
    src_port: reader.optionalNumber('id.orig_p'),
    dest_ip: reader.requiredString('id.resp_h'),
    dest_port: reader.requiredNumber('id.resp_p'),
    proto: reader.requiredString('proto'),
    service: reader.unsetAwareString('service', ZEEK_UNSET),
    duration: reader.optionalNumber('duration'),
    orig_bytes: origBytes,
    resp_bytes: respBytes,
    // `bytes_sent` / `bytes_received` are the names the data-transfer scorer reads;
    // the raw log carries one name per value, so ingest re-derives the alias.
    bytes_sent: origBytes,
    bytes_received: respBytes,
    conn_state: reader.optionalString('conn_state'),
    history: reader.optionalString('history'),
    orig_pkts: reader.optionalNumber('orig_pkts'),
    resp_pkts: reader.optionalNumber('resp_pkts'),
    zeek_uid: reader.optionalString('uid'),
    domain: 'traditional',
  });

  return { dialect: ZEEK_CONN_DIALECT, timestampMs, event, origin: reader.label };
}
```

**Signature.** One raw record in, one `ParsedEvent` out. A `RawRecord` is the decoded JSON
object plus its file and line number; a `ParsedEvent` is the normalized event *without its
id*, plus the ordering keys the merge needs.

```ts
interface ParsedEvent {
  dialect: DialectKind;   // 'zeek/conn' — also the tiebreak rank key
  timestampMs: number;    // the primary sort key
  event: Record<string, unknown>;  // normalized fields, id excluded
  origin: string;         // 'conn.log:412', for ambiguity reports
}
```

Note what is **not** there: no `id`. The parser must not assign one. Ids come from the
merge, after every dialect has been read, and a parser that invents ids breaks the
reconstruction.

**Read through `RecordReader`, never off the raw object.** Every accessor reports
`file:line` on failure, so a bad estate log points at itself instead of surfacing as an
`undefined` three stages downstream.

| Accessor | Behavior |
| --- | --- |
| `requiredString(key)` | non-empty string, or error |
| `optionalString(key)` | absent/`null` → `undefined`; a present non-string is an error, not a coercion |
| `unsetAwareString(key, token)` | as above, but the dialect's unset token (`-`) and `''` both decode to `undefined` |
| `requiredNumber(key)` / `optionalNumber(key)` | finite JSON numbers only; a quoted number gets the shipper hint |
| `optionalBoolean(key)` | strict boolean |
| `optionalScalar(key)` | string, number or boolean — for a field whose wire type varies across estates |
| `optionalStringArray(key)` | `string[]` |
| `zeekTimestampMs(key?)` | epoch seconds → ms; names the ISO-timestamps setting if it sees one |
| `sysmonTimestampMs(key?)` | `YYYY-MM-DD HH:MM:SS.mmm` → ms |
| `isoTimestampMs(key)` | ISO 8601 → ms; zone-less is UTC, a locale stamp is refused |

**`compact()` drops `undefined`, keeps `null`.** That is what lets the parser write every
field unconditionally and still produce a record with no invented keys. The distinction is
load-bearing: `null` means "the source said nothing here", an absent key means "this
dialect has no such column".

**Write the field names the pipeline reads.** The `bytes_sent` / `bytes_received` aliases
above are the clearest case — the log carries `orig_bytes`, the scorer reads `bytes_sent`,
so the parser writes both. Check the "Read by" column in [schema.md](schema.md) before
deciding a field is optional.

**Timestamps are UTC, always.** Convert to epoch milliseconds, then `isoFromMs()`. Never
hand a local-time string through: it would make the machine's timezone an input to the
event ids.

### Wiring a new dialect in

Four edits, all in `src/ingest/`.

**1. Declare the dialect** in [`merge.ts`](../src/ingest/merge.ts):

```ts
export const DIALECT_KINDS = [
  'zeek/conn',
  // …
  'your/dialect',
] as const;
```

**2. Give it an ordering rank**, in the same file:

```ts
export const DIALECT_ORDER_RANK: Readonly<Record<string, number>> = {
  'zeek/conn': 0,
  'sysmon/network_connect': 1,
  'zeek/ssl': 2,
  'sysmon/process_create': 3,
  'your/dialect': 4,
};
```

The rank breaks ties between records sharing a timestamp. A dialect with no entry sorts
last (`MAX_SAFE_INTEGER`), which works but leaves the order at the mercy of the fallback.
Give it a number.

**Adding a rank to an existing dialect's position changes ids for everyone.** The rank
table is a contract with the id sequence: reordering it renumbers events in any folder
where two dialects share a millisecond, and every content-derived candidate id changes
with them. Append; do not renumber.

**3. Register the parser** in [`index.ts`](../src/ingest/index.ts):

```ts
const PARSER_BY_KIND: Record<DialectKind, RecordParser> = {
  // …
  [YOUR_DIALECT]: parseYourRecord,
};
```

**4. Teach classification to recognize it.** Two mechanisms, and a file only needs to
match one:

```ts
// By filename — most specific pattern first.
const NAME_RULES: ReadonlyArray<readonly [RegExp, FileKind]> = [
  [/(^|[^a-z0-9])your[_-]?logs?([^a-z0-9]|$)/i, YOUR_DIALECT],
  // …
];

// By the shape of the first record, when the name says nothing.
export function classifyByRecord(record: Record<string, unknown>): FileKind | undefined {
  if ('YourDistinctiveField' in record) return YOUR_DIALECT;
  // …
}
```

Order in `NAME_RULES` is significant: `network_connect` is tested before the bare `conn`
rule so a `sysmon-network_connect.jsonl` is never read as a Zeek conn.log. Put your
pattern where it cannot be shadowed by a looser one above it.

A trailing `.gz` is stripped before name matching, and gzip is decompressed before your
parser sees a single byte — you get nothing for free by handling compression, and nothing
to handle.

### If your format is not JSON lines

Every current dialect is JSON lines, and `parseJsonLines` is applied before dispatch. A CSV
or XML dialect needs a different reader, which means changing how `ingestFolder` turns a
file's text into `RawRecord`s rather than adding a parser beside the existing ones. Route 2
is usually the better answer for those formats — convert to normalized events with the
tools that already read your format well.

## Knowing it works

**Round-trip one record by hand first.** Take a real line from your logs, run it through
your parser in a scratch test, and check every field against the "Read by" column in
[schema.md](schema.md). A parser that produces a plausible object which omits `dest_ip`
scores nothing and reports no error.

**Then write the tests.** The existing dialect suites in `test/ingest/` are the model, and
each one makes the same four claims:

- a valid record produces the expected normalized event, field by field;
- a record missing a required field errors, and the message names the file, the line and
  the field;
- the dialect's unset token decodes to the right absence;
- the folder scan classifies the file correctly, by name and by content.

**Then run the pins.** `npm test` includes three conformance pins that push the sample
dataset through the pipeline from three different entry points and assert byte-for-byte
equality with the committed golden. A new dialect should not move them — if it does, the
change reached further than ingest and you want to know that before anything else.

```bash
npm test
npm run smoke   # the compiled CLI over fixtures/raw, byte-checked against the golden
```

**Then run it on real data and read the summary.** Event counts per file, what the scan
passed over, what the schema loader refused, and — the one that catches a broken
timestamp conversion — whether the ordering rule reported ambiguities it should not have.

## Adding a scorer

The other extension surface. `powershell/script_block` events are already parsed,
normalized, merged, keyed into the script-block-hash frequency table, and served by a
working `script_block_hash_rarity` stamper. No candidate type declares those labels
applicable, so nothing consumes any of it.

A new candidate type needs, roughly:

- an interface in [`src/schema/candidates.ts`](../src/schema/candidates.ts);
- a scorer in `src/pipeline/score/` that takes selected events and returns candidates with
  a `<type>_score`, an `evidence.constituent_event_ids` array, and deterministic ids from
  `assignDeterministicCandidateIds`;
- a selector in [`src/run/select.ts`](../src/run/select.ts) for the events it reads;
- a runner in `src/run/runners/`, built with `createDistillationRunner`;
- an entry in `RUNNER_BY_CANDIDATE` in [`src/run/runner.ts`](../src/run/runner.ts) and in
  the default `distill_candidates` list;
- an applicability entry in
  [`src/pipeline/spec/enrichment-spec.ts`](../src/pipeline/spec/enrichment-spec.ts) naming
  which enrichment labels the type carries.

The scorer sees only the events its selector picked. Attribution, the frequency tables and
stage-4 enrichment all see the full event set. [design.md](design.md) explains why that
split exists.
