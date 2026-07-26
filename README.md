# athanor

**Raw telemetry in, scored candidates out.** A folder of Zeek and Sysmon logs goes in;
a JSON file of scored, enriched, evidence-linked candidates comes out. One command, no
services, no database, no network calls.

```bash
npx @aionsec/athanor ./telemetry/
```

An *athanor* is the slow furnace an alchemist kept at a steady heat for days while a
mixture reduced to whatever was actually in it. That is the job here. Security telemetry
arrives in volumes no analyst and no language model can read: hundreds of thousands of
lines in which a handful of things are worth a human minute. Distillation is the step
that turns that volume into a short, scored, ranked list — and in most tooling it is the
step you are not allowed to look at. It happens inside a product, behind a score you
cannot reproduce, on rules you cannot read.

athanor is that step, extracted and handed over. Every threshold is in a file you can
open, every score is arithmetic you can follow, and the same folder distills to the same
bytes on any machine. It ships five candidate types, a complete pipeline, and a sample
intrusion dataset to run it against.

It is MIT-licensed and stands alone. It also accompanies AionSec's Agentic Security
Engineering course (<https://aionsec.ai>), where the distillation stage it implements is
the seam the rest of the material is built on.

---

## Quickstart

Node 22 or newer.

```bash
# Distill a folder of logs into ./candidates.json
npx @aionsec/athanor ./telemetry/

# Choose the output path, and keep what the emit floors dropped
npx @aionsec/athanor ./telemetry/ -o candidates.json --discards caput.json
```

Or from a clone, which also gets you the sample dataset:

```bash
git clone https://github.com/aionsec/athanor && cd athanor
npm install && npm run build
node dist/cli.js ./fixtures/raw -o candidates.json
```

That last command prints:

```
athanor: 3859 events from 4 files in ./fixtures/raw
  conn.log           zeek/conn                 1614
  ssl.log            zeek/ssl                   480
  sysmon-eid1.jsonl  sysmon/process_create      151
  sysmon-eid3.jsonl  sysmon/network_connect    1614
candidates: 10
  beacon                            5
  data_transfer                     1
  tls_anomaly                       1
  unusual_parent_child_anomaly      2
  powershell_invocation_anomaly     1   (3 below the 0.6 floor)
caput mortuum (dropped by the emit floors): 3
wrote /…/candidates.json
```

3,859 events to 10 candidates. The summary goes to stderr, the JSON to the output path,
so `-o /dev/stdout | jq` works.

```
Usage: athanor <telemetry-dir> [options]

Distills a folder of raw telemetry into scored candidates. Recognized dialects:
Zeek conn.log / ssl.log (JSON lines), Sysmon EID 1 / EID 3 JSONL, PowerShell 4104
JSONL, or a single already-normalized events.json.

Options:
  -o, --output <path>    where to write the candidates (default: candidates.json)
      --config <path>    athanor.yaml; without it the built-in defaults apply.
                         Merged per key: what it names wins, what it does not name
                         keeps the default, and a key set to null is removed
      --discards <path>  also write the caput mortuum — the candidates the emit
                         floors dropped
      --version          print the version and exit
  -h, --help             show this help

Exit codes: 0 = distilled, 1 = bad usage, unreadable input or unwritable output.
```

## What comes out

Each candidate is a JSON object carrying its own score, the features that produced the
score, the ids of every event it was built from, an attribution block (which process on
which host, and how confident that link is), and an enrichment block. Nothing is a bare
number without its inputs.

| Type | Reads | Scores |
| --- | --- | --- |
| `beacon` | Zeek `conn` | interval regularity, byte and duration consistency, hourly coverage |
| `data_transfer` | Zeek `conn` | producer-consumer ratio and outbound volume |
| `tls_anomaly` | Zeek `ssl` | certificate, JA3/JA4 fingerprint and SNI anomalies (strongest signal wins) |
| `unusual_parent_child_anomaly` | Sysmon EID 1 | parent-child process pairs against a tiered taxonomy |
| `powershell_invocation_anomaly` | Sysmon EID 1 (+ EID 7) | rename, custom host, parent and command-line dimensions |

Every candidate then passes through the same back half: attribution against Sysmon EID 3,
local frequency analysis over nine entity tables, and enrichment (rarity, first-seen,
geo, business-hours proportion, threat-intel and protocol-mismatch flags). See
[docs/design.md](docs/design.md) for the stage-by-stage account.

## Supported inputs

Point athanor at a **directory**. It reads the files in that directory — it does not
descend into subdirectories.

| Input | Recognized as | Notes |
| --- | --- | --- |
| Zeek `conn.log` | `zeek/conn` | JSON lines, epoch-second `ts` |
| Zeek `ssl.log` | `zeek/ssl` | JSON lines, pre-joined with x509 certificate columns |
| Sysmon EID 1 JSONL | `sysmon/process_create` | native Sysmon field names, one flat object per line |
| Sysmon EID 3 JSONL | `sysmon/network_connect` | same; a mixed EID 1 + EID 3 file is dispatched per line |
| PowerShell 4104 JSONL | `powershell/script_block` | parsed and normalized; **no scorer reads it in v1** |
| `events.json` | normalized events | an array of already-normalized events, ids trusted as written |

Files are classified by name first (`conn.log`, `sysmon-eid3.jsonl`, `ssl.log.gz`) and by
the shape of their first record second, so an unhelpfully named export still lands in the
right lane. A file athanor cannot classify is an **error**, not a skip: silently ignoring
a log file is silently losing evidence.

Rotated `.gz` logs are read directly — the magic bytes decide, so a mislabeled file works
too. Any other container (zstd, xz, bzip2, zip, lz4, 7-zip, tar) is named and left for you
to unpack. UTF-8 byte-order marks are stripped; a UTF-16 export is refused with a message
saying so.

An `athanor.yaml`, and whatever file you named with `--config`, are skipped and reported
if they happen to sit inside the telemetry folder. Configuration is not evidence.

## What v1 does not do

**JSON logs only.** Zeek's *default* ASCII (tab-separated) logs are not supported. Re-run
Zeek with `redef LogAscii::use_json=T;` in `local.zeek`, or use the `json-streaming-logs`
package. That case is refused by name rather than left to fail as "malformed JSON".
athanor also reads Zeek's default epoch-second timestamps, not the `JSON::TS_ISO8601` form.

**The PowerShell 4104 lane is parsed but not scored.** Script-block records are read,
validated, normalized and merged into the event stream — and then no scorer consumes
them, because none of the five candidate types reads script blocks. The lane exists as the
worked example for extending ingest, and the plumbing behind it is real: the frequency
tables and the rarity enrichment already know how to key on a script-block hash. Writing
the scorer that uses it is the natural first contribution.
[docs/extending.md](docs/extending.md) walks the lane end to end.

**Sysmon EID 7 (`image_load`) has no raw parser.** The PowerShell scorer reads image-load
events to spot a custom PowerShell host, and the normalized schema defines them — but
ingest has no EID 7 dialect, so the only way to supply them today is the `events.json`
lane. On a folder of raw Sysmon logs that dimension never fires.

**The known-bad TLS fingerprint sets are empty.** The TLS scorer's JA3, JA3S, JA3+JA3S
pair and JA4X sets ship empty, so its fingerprint dimension always scores 0 under the
default configuration; `tls_anomaly` candidates come from the certificate and SNI
dimensions alone. Those sets are a scorer-level constant, not something `athanor.yaml`
reaches.

**The bundled reference tables are placeholders.** `data/geoip/minimal.json`,
`data/lots/minimal.json` and `data/threat-intel/minimal.json` hold a handful of
documentation addresses between them. On real telemetry, `geo_country`, `geo_asn`,
`lots_match` and `threat_intel_match` will report nothing until you replace those files
with tables of your own. The taxonomies that drive the process scorers
(`data/unusual-parent-child-anomaly/`, `data/powershell-invocation/`) are real and
complete; the three lookup tables are not.

**athanor is an in-memory kit.** Every file is read whole and every event stays resident.
That is right for a course dataset or a day of one estate's logs, and wrong for a
multi-gigabyte export: slice big estates into folders you can hold in memory rather than
pointing athanor at all of it at once.

## Ids, and what changes them

**Event ids are reconstructed, not read.** Raw logs carry no event ids. athanor sorts
every parsed record from every dialect together — by timestamp, then by a fixed
per-dialect rank — and numbers the result `evt-00001`, `evt-00002`, and so on.

One consequence surprises people: **adding a file to a folder renumbers the events.** A record inserted mid-stream shifts every later id by
one, and since candidate ids are content hashes computed over records that include those
event ids, the candidate ids change with them. The same folder always distills to the same
bytes; a folder with one more log file in it does not.

Two smaller cases the run reports rather than hides:

- When two records tie on both sort keys, the rule cannot separate them, and the merge
  falls back to file and line order. That is stable for a given folder and not stable
  across a re-ordered export — so the CLI warns and names the pairs.
- Timestamps are read as UTC regardless of the machine's timezone. A `TimeCreated` with no
  zone is UTC, and a locale-format stamp is refused rather than guessed at, so the same
  folder distills identically in every timezone.

Presentation ids (`BCN-001`, `DT-001`, `TLS-001`, `UPCA-001`, `PSI-001`) are assigned last,
by rank within each type. They are labels for reading a single run's output, not
identities: the candidate that is `BCN-002` today is `BCN-003` tomorrow if a stronger
beacon appears. The content-derived id is preserved as `pipeline_candidate_id`, and that
one is stable for as long as the candidate's contents are.

## Emit floors, and the caput mortuum

Each candidate type has a minimum score. A candidate below its floor is not emitted. The
defaults are `beacon` 0.40, `tls_anomaly` 0.40, `powershell_invocation_anomaly` 0.60,
`unusual_parent_child_anomaly` 0.60, and no floor at all for `data_transfer`.

A threshold that deletes evidence without saying so is the thing this tool exists to
argue against, so the count is always printed and `--discards <path>` writes the discarded
pile itself. It is called the **caput mortuum** — the "dead head", what alchemists named
the residue left in the vessel once distillation had taken everything useful out of it.
Reading it is how you find out that your floor was set wrong.

## Config

`--config <path>` names a YAML file. Without it, the built-in defaults apply. athanor never
picks up a stray `athanor.yaml` from the working directory, because a config that is found
rather than named changes scores without anyone asking.

The file is merged into the defaults **per key**, and the whole rule is three lines:

1. a key you name takes your value;
2. a key you do not name keeps its default;
3. a key you set to `null` is removed.

So this config, meant to see more beacons, changes the beacon floor and nothing else — the
`powershell_invocation_anomaly` (0.6), `unusual_parent_child_anomaly` (0.6) and
`tls_anomaly` (0.4) floors all stand:

```yaml
emit_floors:
  beacon: 0.2
```

and this one clears the TLS floor while keeping the rest, so every `tls_anomaly` candidate
is emitted however low it scores:

```yaml
emit_floors:
  tls_anomaly: null
```

`emit_floors: null` clears them all. The same three rules govern `presentation_ids`,
including its `prefixes` map, key by key. `distill_candidates` is the one exception: it is
a list rather than a mapping, so declaring it replaces the list — and declaring it *empty*
is an error rather than a run that quietly distills nothing.

Every run that used a `--config` prints one line naming what the file overrode and what it
removed:

```
config: /estate/athanor.yaml — 1 key overridden (emit_floors.beacon), 1 removed (emit_floors.tls_anomaly); every key the config does not name keeps its built-in default
```

## Sample data

`fixtures/raw/` is a synthetic intrusion scenario: four raw dialect files, 3,859 events
across 26 hosts, one compromised workstation, several perfectly ordinary things that score
high, and ten candidates at the other end. Nothing in it was captured from a real network.
[fixtures/README.md](fixtures/README.md) describes what is in the dataset and what each
candidate is looking at.

It is also the test contract. Three conformance pins enter the pipeline at three different
points — raw folder, normalized events, pre-enriched events — and each asserts that the
result is byte-for-byte identical to the committed golden file.

## Documentation

- **[docs/schema.md](docs/schema.md)** — the normalized event schema: every event type,
  every field, every format, and the rules that admit or refuse a record.
- **[docs/extending.md](docs/extending.md)** — write a converter for your own log format.
  One existing parser walked through line by line, then what to add and how to prove it
  works.
- **[docs/design.md](docs/design.md)** — how the pipeline is built and why: the stages,
  the floors, determinism and canonical serialization, and the testing philosophy.

## Development

```bash
npm test              # unit suites, the canon contract and the three conformance pins
npm run typecheck
npm run build         # → dist/
npm run smoke         # re-runs the compiled CLI over fixtures/raw against the golden
npm run smoke:install # packs the tarball, installs it clean, runs the INSTALLED bin
```

The two smokes are packaging tripwires and they catch different things. `npm run smoke`
proves the *compiled* CLI still reproduces `fixtures/candidates_enriched.json` byte for
byte, which is what catches a build layout that breaks `data/` resolution — a failure that
produces different scores rather than an error. `npm run smoke:install` proves the
*packaged* CLI does, installed into a clean prefix from the tarball, so a `files` list that
forgot `data/`, a runtime dependency left in `devDependencies`, or a bin that does not
resolve all surface here rather than in someone's terminal. Run both after touching
`tsconfig.build.json` or the `files` / `bin` / `dependencies` fields.

## Contributing

Issues and pull requests are welcome. The most useful contributions, roughly in order:

1. **A converter for a log format athanor does not read.** EDR exports, Windows Event Log
   JSON, Suricata EVE, cloud audit logs. [docs/extending.md](docs/extending.md) is written
   for exactly this.
2. **A scorer for the 4104 lane** — the events are already there, unused.
3. **Real reference tables** to replace the three placeholder lookups.
4. **Bug reports with the telemetry that caused them**, synthetic or redacted.

One rule governs everything else: `fixtures/candidates_enriched.json` is a contract, not
an output. If a change moves it, the change is what needs explaining.

## License

MIT — see [LICENSE](LICENSE).
