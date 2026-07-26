# How athanor is built, and why

athanor turns a folder of raw logs into a short list of scored candidates. This document
explains the pipeline that does it — what each stage sees, why the stages are ordered the
way they are, and which properties the design protects at the cost of others.

## The problem

A modest estate produces hundreds of thousands of log lines a day. Perhaps a dozen are
worth a human minute. Everything in security operations that comes after — triage,
investigation, hunting, any use of a language model on telemetry — depends on some
mechanism that reduces the first number to the second.

That mechanism is usually invisible. It lives inside a product, produces a score whose
derivation is not published, and applies thresholds you can neither read nor change. When
it drops something, you find out by not seeing it.

athanor is that mechanism written out. Every threshold is in a file you can open, every
score is arithmetic with named inputs, every discard is counted and can be written to disk,
and the same folder produces the same bytes on any machine.

The name comes from the alchemists' *athanor* — the slow furnace held at a steady heat for
days while a mixture reduced to whatever was actually in it. Distillation, applied to
telemetry, is the same operation: sustained, unhurried reduction, where what leaves the
vessel is a fraction of what entered and the discarded fraction is not thereby unimportant.

## The pipeline

Six stages, in one direction, no loops.

```
  raw log files
        │
        ▼
  ┌───────────────┐
  │ 1  ingest     │  one parser per dialect → merge by (timestamp, dialect rank)
  │               │  → assign evt-00001…                    [src/ingest/]
  └───────┬───────┘
          ▼
  ┌───────────────┐
  │ 2  enrich     │  attach an `enrichment` block to every event
  │    events     │  (business hours, and any labels an upstream tool set)
  └───────┬───────┘                                     [src/enrich-events/]
          ▼
  ┌───────────────┐
  │ 3  score      │  per candidate type: select the events it reads, group them
  │               │  into entities, compute features, emit scored candidates
  └───────┬───────┘                                  [src/pipeline/score/]
          ▼
  ┌───────────────┐
  │ 3B attribute  │  network candidate → the process that made the connection
  └───────┬───────┘                                [src/pipeline/attribute/]
          ▼
  ┌───────────────┐
  │ 3C local      │  nine frequency tables over the full event set:
  │    frequency  │  how many hosts have seen this entity at all?
  └───────┬───────┘                           [src/pipeline/lfa-precompute/]
          ▼
  ┌───────────────┐
  │ 4  enrich     │  stamp rarity, first-seen, geo, business-hours proportion,
  │    candidates │  threat-intel and protocol-mismatch onto each candidate
  └───────┬───────┘                        [src/pipeline/enrich-candidates/]
          ▼
  ┌───────────────┐
  │ 5  emit       │  drop candidates below their type's floor → caput mortuum
  │    floors     │                                        [src/run/floors.ts]
  └───────┬───────┘
          ▼
  ┌───────────────┐
  │ 6  presentation  rank within each type, assign BCN-001, DT-001, …
  │    ids        │                                  [src/run/presentation.ts]
  └───────┬───────┘
          ▼
   candidates.json
```

Stages 3 through 4 run **once per candidate type**. Stages 1, 2, 5 and 6 run once for the
whole run.

### Which stage sees which events

One rule covers it: **only the scorer sees a subset.** Every per-type run is handed the full stage-2
event set, and its selector narrows that down to the events that scorer reads —
`zeek/conn` for beacon and data transfer, `zeek/ssl` for TLS anomaly, everything for the
two process scorers. Attribution, the frequency tables and stage-4 enrichment all work
over the complete set.

That asymmetry is deliberate. A beacon scorer that only ever saw connection records could
not be attributed to a process, and rarity computed over a filtered event set would answer
a different question than the one it appears to answer — "rare among connection records"
is not "rare on this estate".

Each per-type run also gets its own copy of the event array. A scorer that sorted or
spliced its input would otherwise reorder the evidence and corrupt the frequency tables of
whatever ran next.

### Stage 1: ingest

One parser per dialect, each the inverse of the shape a real collector emits, then a merge.
Raw logs carry no event ids, so ingest reconstructs them: sort every parsed record from
every dialect by `(timestamp in ms, dialect rank)`, number the result `evt-%05d`.

The consequence is unavoidable: **event ids are a property of the folder, not of the
records.** Adding a file renumbers everything after the first
record it inserts. See [Determinism](#determinism) for what that costs downstream.

Nothing here is lenient by default. An unclassifiable file, a malformed line and an empty
folder are all hard errors. What a folder scan legitimately cannot ingest — a
subdirectory, a broken symlink, a config file, a record the normalized loader refuses — is
*reported*, never dropped silently. Skipping is allowed to be legitimate; it is not
allowed to be quiet.

### Stage 2: event enrichment

Attaches an `enrichment` block to every event. athanor computes exactly one label,
`business_hours`, from a config file. The other six (`lolbas_match`, `hijacklibs_match`,
`filesec_match`, `persistence_path_class`, `security_tool_name`, `account_type`) are
carried through when an upstream tool has already set them and left `null` otherwise.

Which labels apply depends on the event type, and the applicability map is explicit rather
than inferred: an EID 1 process create carries six of them, a Zeek connection carries one.
A label that does not apply to an event type is absent rather than null, so "not
applicable" and "applicable but unknown" stay distinguishable.

Stage 2 is pure — same events in, same events out — which is what lets it be hoisted out of
the per-type loop and run once instead of five times.

### Stage 3: scoring

Five scorers, each independent. All five follow the same shape: group events into
**entities**, compute features per entity, combine features into a composite score in
`[0, 1]`, attach the ids of every contributing event.

The entity key is where a scorer decides what it is counting.

| Type | Entity | Composite |
| --- | --- | --- |
| `beacon` | `(src_ip, dest_ip, dest_port)` | weighted sum |
| `data_transfer` | `(src_ip, dest_ip, dest_port)` | weighted sum |
| `tls_anomaly` | `(src_ip, dest_ip, dest_port)` | max of dimensions |
| `unusual_parent_child_anomaly` | one process-create event | tier lookup |
| `powershell_invocation_anomaly` | one process-create event | max of dimensions |

**Weighted sums** are for candidates where the evidence accumulates. A beacon is regular
*and* consistent in bytes *and* consistent in duration *and* active across many hours; each
of those is weak alone and the combination is the signal. Beacon weights regularity at
0.30, byte consistency at 0.15 each, duration consistency at 0.10, the hourly histogram at
0.15 and consecutive-hour coverage at 0.15. Data transfer is a two-term sum: producer-
consumer ratio and normalized outbound volume, 0.50 each.

**Max-of-dimensions** is for candidates where the evidence is alternative rather than
cumulative. A TLS connection with a self-signed certificate is suspicious; one with a
known-bad JA3 is suspicious; one with no SNI at all is suspicious. They are three
independent reasons, not three parts of one reason, and averaging them would let two
clean dimensions dilute one strong one. The strongest dimension wins, and the candidate
records all of them so you can see which.

The thresholds and weights each scorer uses are exported constants with default values in
the same file. Nothing is buried — but nothing is reachable from `athanor.yaml` either.
The config file covers candidate types, emit floors and presentation ids; changing a
scorer's weights means editing the constant or calling the scorer from your own code with
a config of your own.

One consequence to know about: the TLS scorer's four **known-bad fingerprint sets default
to empty**. With the shipped configuration its fingerprint dimension always scores 0, and
`tls_anomaly` candidates come from the certificate and SNI dimensions alone.

### Stage 3B: attribution

A network candidate knows a connection. An analyst needs a process. Attribution walks the
bridge: from the candidate's constituent Zeek connection records, through Sysmon EID 3
network-connect events matched on the four-tuple within a 2-second skew window, to the
EID 1 process-create event that shares the EID 3's `process_guid`.

Only the three network types — `beacon`, `data_transfer`, `tls_anomaly` — are attribution-
eligible. The two process candidate types are built from EID 1 events and already carry
process identity, so there is no bridge to walk.

The result carries a **confidence**, and the failure modes are named rather than blank:
`full`, `partial_time_skew`, `partial_multi_process`, `inferred`, `unavailable`, plus
`data_quality_flags` saying which of `no_eid3_match`, `multi_process_match`,
`time_skew_exceeded`, `missing_process_create` or `partial_evidence_unattributed` applied.

In the sample dataset, `TLS-001` comes out `unavailable` with
`[no_eid3_match, partial_evidence_unattributed]` — the Zeek ssl records carry connection
ids that do not join to any conn record, so the bridge has no first span. That is what a
real join failure looks like, and it is in the sample data on purpose.

### Stage 3C: local frequency analysis

Nine tables, each mapping an entity to the number of distinct hosts that have been seen
with it: destinations, process names, command lines, file hashes, parent-child pairs,
script-block hashes, domains, user agents and JA3 fingerprints.

From those counts come **prevalence** (hosts with this entity ÷ hosts in the population)
and **rarity** (`1 − prevalence`). The population is every host in the run — the `host`
field where an event has one, `src_ip` otherwise.

This is the stage that turns "this destination" into "this destination, which one host out
of 26 has ever contacted". It is also the stage most sensitive to what you feed it: rarity
over one workstation's logs is a statement about that workstation, and calling it rarity
invites reading it as a statement about the estate.

### Stage 4: candidate enrichment

Stamps the labels applicable to each candidate type: rarity and raw frequency for the
relevant entity kinds, first-seen timestamp, business-hours proportion, geo country and
ASN, LOTS (living-off-trusted-sites) domain match, missing SNI, threat-intel match,
protocol mismatch.

Applicability is declared per candidate type, not inferred. A beacon carries sixteen
labels, an unusual parent-child anomaly carries six. A label a type does not declare is
never stamped, and a label with no stamper behind it cannot be declared — a schema field
nothing can produce is a promise the output cannot keep.

Three of the lookup tables that ship — geo, LOTS domains, threat intel — are placeholders
holding a handful of documentation addresses. On real telemetry those
four labels report nothing until the tables are replaced. The taxonomies driving the two
process scorers are real and complete.

### Stage 5: emit floors, and the caput mortuum

Each candidate type has a minimum score. Below it, a candidate is not emitted. The
defaults are `beacon` 0.40, `tls_anomaly` 0.40, `powershell_invocation_anomaly` 0.60,
`unusual_parent_child_anomaly` 0.60, and no floor at all for `data_transfer`.

Floors exist because a distillation with no floor is not a distillation. Every entity that
clears a scorer's minimum evidence threshold produces a candidate, and most of them score
low for the good reason that they are ordinary. Emitting all of them hands the next stage —
an analyst, or a model — the volume problem back.

But a threshold that deletes evidence without saying so is precisely the thing this tool
argues against. So the floors do not delete. They **partition**. What falls below the
floor goes into a second collection that the run keeps, counts in its summary, and writes
to disk on request:

```bash
npx @aionsec/athanor ./telemetry/ --discards caput.json
```

That collection is the **caput mortuum** — literally "dead head", the alchemists' name for
the residue left in the vessel after distillation had drawn off everything volatile. It
was the definitionally worthless part, the *dead* head, and the name stuck hard enough that
it later became a pigment: the dull purple-brown of iron oxide, sold under the name of the
thing nobody wanted.

The name is a joke with a point in it. The alchemists were regularly wrong about their
residue, and so is any emit floor. A floor set too high is invisible from the output side —
you cannot see what you did not receive — and the only way to audit one is to read what it
discarded. In the sample dataset the caput mortuum holds three PowerShell-invocation
candidates at exactly 0.5, below the 0.6 floor: three ordinary service binaries launched by
`services.exe`, each scoring on the parent dimension alone. Correctly dropped, and the only
way to confirm that is to look.

### Stage 6: presentation ids

Every candidate already has an id: `<PREFIX>-` plus the first 16 hex characters of a
SHA-256 over its own contents. Content-derived, stable across machines, and unreadable
aloud.

Presentation ids are the human-facing layer. Candidates are ranked by score within their
type and numbered: `BCN-001` through `BCN-005`, `DT-001`, `TLS-001`, `UPCA-001`,
`UPCA-002`, `PSI-001`. The content id is preserved as `pipeline_candidate_id`.

**A presentation id is a label for one run's output, not an identity.** They are assigned
by rank, so the candidate that is `BCN-002` in today's run is `BCN-003` tomorrow if a
stronger beacon appears — and `BCN-002` in a different folder is a different thing
entirely. Across runs, compare on `pipeline_candidate_id`. Presentation ids are for
reading a report; content ids are for tracking a candidate.

## Determinism

The same input produces the same output, byte for byte, on any machine. That is a design
constraint, not an aspiration, and several pieces of the implementation exist only to hold
it.

**Canonical serialization.** Output goes through one serializer: object keys sorted,
`undefined` values dropped, every number rounded to 6 decimal places, two-space indent, a
trailing newline. Without the rounding, floating-point arithmetic that differs in the
sixteenth decimal across platforms would produce different bytes for identical results.

**Content-derived ids.** A candidate's id is a SHA-256 over the candidate itself with its
id field removed, serialized canonically with arrays sorted as well as keys. Identical
candidates get identical ids, everywhere, with no counter and no run state.

**UTC everywhere.** Zeek epoch seconds are timezone-free by construction. Sysmon `UtcTime`
is UTC by name. A PowerShell `TimeCreated` with no offset is read as UTC rather than in
the local zone — reading it locally would make `TZ` an input to the event stream, and the
same folder would distill differently on a laptop and a build machine.

**Sorted file reads.** The folder scan reads files in sorted-name order and each file in
line order, so the merge's stable sort has a defined starting point.

What determinism does **not** promise: that ids survive a change of input. They do not,
and the mechanism is worth understanding rather than working around.

- Event ids come from position in the global timestamp sort. Adding a log file to the
  folder inserts records into that sequence, and every event after the first insertion
  shifts by one.
- Candidate ids are content hashes over records that include `evidence.constituent_event_ids`.
  When the event ids shift, the candidate's contents change, so its content id changes —
  even though the candidate describes exactly the same behavior.
- Presentation ids come from rank, so any change in the set of emitted candidates can
  renumber them.

The same folder always distills to the same bytes. A folder with one more file in it is a
different input, and athanor treats it as one. If you need ids that survive the arrival of
new telemetry, they have to be derived from the behavior rather than from the evidence
list — which is a real design, and not this one.

## Conformance testing

The core of the test suite is not unit tests. It is three **conformance pins** and a
committed golden file.

`fixtures/candidates_enriched.json` is the expected output for the sample dataset: ten
candidates, fully scored, attributed and enriched. Each pin enters the pipeline at a
different point and asserts that what comes out is byte-for-byte identical to it.

| Pin | Entry point | Proves |
| --- | --- | --- |
| **A** | `fixtures/events.json` → full pipeline | stages 2–6 are faithful given normalized events |
| **B** | `fixtures/events_enriched.json` → stages 3–6 | scorers and the back half are faithful given enriched events |
| **C** | `fixtures/raw/` → ingest → full pipeline | the ingest layer is faithful given the shapes a collector emits |

Three entry points rather than one because a single end-to-end test tells you that
something broke, and these tell you *where*. If A fails and B passes, the fault is in
stage 2. If C fails and A passes, the fault is in ingest. Pin C makes that explicit by
asserting an intermediate result first: the ingested events must equal
`fixtures/events.json` before the candidates are compared at all, so an ingest defect
reports as a divergent event id rather than as a candidate diff.

**Byte equality, not structural comparison.** A tolerance-based assertion accepts a change
it should have caught; a byte comparison over a canonical serialization does not. The cost
is that every intentional change to the output shape requires regenerating the golden — and
that cost is the feature. A pin failure means the code moved. Fix the code, not the
fixture, or explain the change.

Two more gates cover packaging, which the pins cannot see:

- `npm run smoke` runs the **compiled** CLI over the sample data and byte-checks the
  result. This is what catches a build layout that breaks `data/` path resolution — a
  failure that produces *different scores* rather than an error, because the taxonomy
  loaders fall back to empty tables when their files are missing.
- `npm run smoke:install` packs the tarball, installs it into a clean prefix, and runs the
  **installed** binary. A `files` list that forgot `data/`, a runtime dependency left in
  `devDependencies`, or a bin that does not resolve surface here rather than in someone
  else's terminal.

## What this design leaves out

Stated plainly, because each is a real limit and not an oversight.

- **In-memory only.** Every file is read whole and every event stays resident. Right for a
  day of one estate's logs, wrong for a multi-gigabyte export.
- **No correlation between candidate types.** Five scorers run independently and nothing
  composes their outputs. In the sample dataset, `BCN-002`, `DT-001` and `TLS-001` are the
  same connection seen three ways, and athanor emits three candidates without ever
  observing that. Composing them is a real capability and not one this tool has.
- **No feedback.** Nothing learns from what an analyst did with the output. The floors are
  where you would put that knowledge, and they are static.
- **A single time window.** The run distills whatever is in the folder. There is no notion
  of a baseline period against which the current period is compared — "first seen" is first
  seen *in this folder*.
- **JSON logs only, one directory deep.** No tab-separated Zeek, no subdirectory descent.

Some of these are extension surfaces; see [extending.md](extending.md). Others are the
shape of the tool.
