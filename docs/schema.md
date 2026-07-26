# The normalized event schema

Everything downstream of ingest — the five scorers, attribution, the frequency tables,
enrichment — reads **normalized events**, never raw log lines. A normalized event is a
plain JSON object with a small set of guaranteed fields and whatever else its dialect
carries. This document is the reference for that shape: what each event type looks like,
which fields the pipeline reads, how values are formatted, and what happens to a record
that does not conform.

There are two ways an event enters the pipeline.

- **Raw ingest.** A dialect parser converts one raw log line into one normalized event.
  Ids are reconstructed by the merge (see [Ids](#ids)). A record missing a field its parser
  requires is a **hard error** naming the file and line.
- **The `events.json` lane.** A file holding a JSON array of already-normalized events is
  loaded directly, ids trusted as written. A record that does not conform is **dropped**,
  and the CLI reports how many and at which array indices.

The two regimes differ deliberately. A raw parser knows exactly what it needs and can point
at the offending line, so it refuses. The normalized loader is handed an array by another
tool and can only account for what it discarded — which it does, by index. Neither is
allowed to be quiet.

The TypeScript definitions live in [`src/schema/events.ts`](../src/schema/events.ts) and
are the authority if this document and the code ever disagree.

---

## Fields every event carries

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | `evt-00001`-style. Reconstructed by raw ingest, read as written in the `events.json` lane. |
| `timestamp` | string | ISO 8601, UTC, millisecond precision: `2026-03-09T14:00:23.813Z`. |
| `source` | string | `zeek`, `sysmon` or `powershell`. |
| `event_type` | string | `conn`, `ssl`, `process_create`, `network_connect`, `image_load`, `script_block`. |
| `domain` | string | `traditional`, stamped by every parser. Carried, not read by any scorer. |
| `enrichment` | object | Added by stage 2. Absent on ingest output, present from stage 2 onward. |

`source` and `event_type` together pick the lane. Every interface also permits unknown
extra keys, and they are carried through untouched — a converter can attach fields the
pipeline does not read without breaking anything.

### Timestamps

Every timestamp is ISO 8601, UTC, milliseconds. Each dialect gets there from its own
native form:

| Dialect | Native form | Conversion |
| --- | --- | --- |
| Zeek | `ts`, epoch seconds as a JSON number (`1772636430.0`) | `round(ts * 1000)` → ISO |
| Sysmon | `UtcTime`, `YYYY-MM-DD HH:MM:SS.mmm`, already UTC | parsed strictly; any other shape is refused |
| PowerShell 4104 | `TimeCreated`, ISO 8601 | sub-millisecond digits truncated to ms |

A PowerShell timestamp with **no timezone offset is read as UTC**, never as the local
zone. Reading it locally would make `TZ` an input to the event stream: the same folder
would produce different timestamps, and therefore different ids, on a laptop in one
timezone and a build machine in another. A locale-format stamp (`7/25/2026 5:04:47 PM`) is
refused rather than guessed at.

### Numbers

Numbers must be JSON numbers. A quoted number (`"443"`) is an error — some log shippers
render every field as a string, and athanor names that specifically rather than letting it
surface one field at a time. Serialized output is rounded to **6 decimal places**, so a
Zeek `duration` of `0.09983272307086737` is written `0.099833`.

### Ids

Raw logs carry no event ids. Ingest reconstructs them: every parsed record from every
dialect is sorted together by `(timestamp in ms, dialect rank)` and numbered `evt-%05d`
from 1. The rank table breaks timestamp ties:

```
zeek/conn 0  ·  sysmon/network_connect 1  ·  zeek/ssl 2  ·  sysmon/process_create 3
```

Only the first pair is grounded in data — the network and endpoint views of one connection
routinely share a millisecond. The other two ranks exist to make the ordering total.

Records that tie on **both** keys cannot be separated by the rule. The merge falls back to
file and line order (files are read in sorted-name order, each file in line order), which
is stable for a given folder and not stable across a re-ordered export. The CLI warns and
names the pairs when this happens.

In the `events.json` lane, ids are read from the file. A record with no usable `id` gets
`evt-synth-000001` built from its array index, so an id always exists.

---

## `zeek/conn` — connection records

From Zeek's `conn.log` in JSON-lines form. The input to `beacon` and `data_transfer`
scoring, and the network half of attribution.

**Required for admission:** `timestamp`, `source`, `event_type`, `src_ip`, `dest_ip`,
`dest_port`, `proto`.

| Field | Type | Read by |
| --- | --- | --- |
| `src_ip` | string | entity key, attribution, host population count |
| `src_port` | number? | attribution (absent in the sample dataset; a real estate logs it) |
| `dest_ip` | string | entity key, attribution, destination frequency table |
| `dest_port` | number | entity key, attribution |
| `proto` | string | `tcp` / `udp` / `icmp`. Required for admission, carried, read by no scorer |
| `service` | string? | beacon `observed_service`, data-transfer protocol distribution, protocol-mismatch enrichment. Zeek's `-` and the empty string both decode to *absent* |
| `conn_state` | string? | carried |
| `duration` | number? | seconds; beacon duration consistency |
| `orig_bytes` | number? | payload bytes out; both scorers |
| `resp_bytes` | number? | payload bytes in; both scorers |
| `bytes_sent` | number? | alias of `orig_bytes`, written by the parser |
| `bytes_received` | number? | alias of `resp_bytes`, written by the parser |
| `orig_pkts` | number? | carried |
| `resp_pkts` | number? | carried |
| `zeek_uid` | string? | the ssl → conn join key in attribution |
| `history` | string? | carried |

The two byte aliases exist because the raw log carries one name per value and the
data-transfer scorer reads the other. The parser writes both; a converter for a different
format should do the same.

## `zeek/ssl` — TLS handshake and certificate records

From Zeek's `ssl.log`, pre-joined with `x509.log`. The input to `tls_anomaly` scoring.

**Required for admission:** `timestamp`, `source`, `event_type`, `src_ip`, `dest_ip`,
`dest_port`.

| Field | Type | Read by |
| --- | --- | --- |
| `src_ip`, `dest_ip`, `dest_port` | string, string, number | entity key |
| `zeek_uid` | string? | attribution's ssl → conn join |
| `server_name` | string \| null | SNI dimension; `null` when the handshake carried none |
| `tls_version` | string \| null | carried |
| `cipher` | string \| null | emitted as `cipher_suite` on the candidate |
| `ja3_hash` | string \| null | fingerprint dimension, JA3 frequency table |
| `ja3s_hash` | string \| null | fingerprint dimension |
| `ja4_hash` | string \| null | carried |
| `ja4x_hash` | string \| null | fingerprint dimension |
| `sni_matches_cert` | boolean \| null | SNI dimension |
| `connection_to_ip` | boolean | SNI dimension (a connection with no name at all) |
| `cert_subject` | string \| null | self-signed detection |
| `cert_issuer` | string \| null | self-signed detection |
| `cert_serial` | string \| null | short-serial detection |
| `cert_not_before` | string \| null | ISO 8601 |
| `cert_not_after` | string \| null | ISO 8601 |
| `cert_self_signed` | boolean | certificate dimension |
| `cert_expired` | boolean | certificate dimension |
| `cert_validity_days` | number \| null | certificate dimension |
| `cert_key_type` | string \| null | carried |
| `cert_key_length` | number \| null | carried |
| `cert_san_dns` | string[] | carried |
| `cert_chain_length` | number | carried |

**`null` is a value here, and it is not the same as absent.** For this contract, `null`
means "the certificate data said nothing"; a missing key means "this dialect has no such
column". The Zeek parser maps the unset token `-` to `null` for these string fields and
omits absent numbers, booleans and arrays entirely rather than defaulting them — ingest
does not invent certificate facts.

The `zeek/ssl` parser also dual-writes the raw Zeek column names alongside the normalized
ones (`tls_server_name`, `tls_ja3`, `tls_ja3s`, `tls_subject`, `tls_issuer`), because the
raw log carries one name and the scorer reads the other. The schema loader applies the same
fills to an `events.json` record that carries only the raw names.

## `sysmon/process_create` — Sysmon EID 1

The input to `unusual_parent_child_anomaly` and `powershell_invocation_anomaly` scoring,
and the process half of attribution.

**Required for admission:** `timestamp`, `source`, `event_type`, `event_id`, `host`,
`process_name`, `process_path`, `process_id`, `process_guid`, `parent_process_name`,
`parent_process_path`, `parent_process_id`, `parent_process_guid`, `user`, `command_line`.

| Field | Type | Read by |
| --- | --- | --- |
| `event_id` | number | `1` |
| `host` | string | attribution, host population count, LFA host keying |
| `src_ip` | string? | fallback host key when `host` is a NetBIOS name |
| `process_name` | string | basename of the image; both process scorers, process frequency |
| `process_path` | string | full image path; both process scorers |
| `process_id` | number | attribution |
| `process_guid` | string | attribution's EID 3 → EID 1 join |
| `parent_process_name` | string | both process scorers, parent-child pair frequency |
| `parent_process_path` | string | both process scorers |
| `parent_process_id` | number | carried |
| `parent_process_guid` | string | carried |
| `user` | string | attribution, account-type enrichment |
| `integrity_level` | string | carried |
| `current_directory` | string? | carried |
| `command_line` | string | PowerShell scorer, command-line frequency table |
| `original_file_name` | string \| null | rename detection (a renamed `powershell.exe`) |
| `description` | string \| null | rename detection |
| `product` | string \| null | rename detection |
| `company` | string \| null | rename detection |
| `hashes` | string? | hash frequency table |

`hashes` is **Sysmon's comma-joined wire string**, carried verbatim:

```
MD5=9FB70829…,SHA256=D4C3F6CA…,IMPHASH=FEDD09C8…
```

The pipeline parses the SHA-256 out of it when it needs one. An object form
(`{"sha256": "…"}`) and a bare `sha256` field are both accepted as well. Sysmon's unset
token `-` decodes to *absent*, not to a literal `"-"` — otherwise every hash-less process
on the estate would share one entity in the frequency table.

The four PE-metadata fields use `string | null`, and `-` decodes to `null` for them.

## `sysmon/network_connect` — Sysmon EID 3

The endpoint view of a connection. No scorer reads EID 3 directly; it is the bridge that
attribution walks from a network candidate to the process that made the connection.

**Required for admission:** `timestamp`, `source`, `event_type`, `event_id`, `host`,
`src_ip`, `src_port`, `dest_ip`, `dest_port`, `protocol`, `process_name`, `process_id`,
`process_guid`, `user`.

| Field | Type | Read by |
| --- | --- | --- |
| `event_id` | number | `3` |
| `host` | string | attribution, host population count |
| `src_ip`, `src_port` | string, number | the four-tuple attribution matches on |
| `dest_ip`, `dest_port` | string, number | the four-tuple attribution matches on |
| `protocol` | string | carried |
| `process_name` | string | the answer attribution is looking for |
| `process_id` | number | attribution |
| `process_guid` | string | the join key onto EID 1 |
| `user` | string | attribution |

There is **no `process_path` on EID 3.** The normalized contract does not define one, and
the Sysmon parser derives `process_name` as the basename of `Image` without emitting a
path.

## `sysmon/image_load` — Sysmon EID 7

Read by the PowerShell scorer to detect a **custom PowerShell host**: a process that loads
`System.Management.Automation.dll` without being a recognized PowerShell host. The scorer
pairs an EID 1 spawn with an EID 7 load on the same `(host, process_guid)` inside a time
window, then scores the loading process against an allowlist.

**Required for admission:** `timestamp`, `source`, `event_type`, `event_id`, `host`,
`process_name`, `image`, `process_id`, `process_guid`, `image_loaded`, `signed`,
`signature`, `signature_status`.

| Field | Type | Read by |
| --- | --- | --- |
| `event_id` | number | `7` |
| `host` | string | LFA host keying |
| `process_name`, `image` | string | the loading process |
| `process_guid` | string | correlation back to the EID 1 spawn |
| `image_loaded` | string | the DLL path the dimension tests |
| `signed`, `signature`, `signature_status` | string | carried |

**Ingest has no EID 7 parser.** This event type is defined, admitted by the schema loader
and consumed by a scorer, but there is no raw dialect lane that produces one — the
`events.json` lane is the only way to supply image-load events today. On a folder of raw
Sysmon logs, the custom-host dimension never fires. Writing that parser is a well-shaped
first contribution; see [extending.md](extending.md).

## `powershell/script_block` — PowerShell EID 4104

Script Block Logging. **Parsed, validated, normalized and merged into the event stream —
and read by no scorer in v1.**

**Required for admission:** `timestamp`, `source`, `event_type`, `event_id`, `host`, and at
least one of `script_block_hash`, `script_block_text`, `script_block_id`.

| Field | Type | Notes |
| --- | --- | --- |
| `event_id` | number | `4104` |
| `host` | string | LFA host keying |
| `src_ip` | string? | fallback host key |
| `script_block_hash` | string? | preferred script-block identity |
| `script_block_text` | string? | identity falls back to `sha256(text)`, with CRLF normalized to LF |
| `script_block_id` | string? | identity falls back to `id:<value>` |
| `script_block_path` | string? | emitted when the raw record carried a non-empty `Path` |
| `message_number`, `message_total` | number? | fragment position, for multi-part blocks |

The identity rule is what the frequency table keys on:
`script_block_hash` if present, otherwise the SHA-256 of the normalized text, otherwise
`id:<script_block_id>`. At least one must be present, which is why admission tests for
*any* of the three.

The **script-block hash frequency table is already computed** for these events, and the
`script_block_hash_rarity` / `script_block_hash_frequency` enrichment labels already exist
and are already wired to a stamper. What is missing is a candidate type that declares them
applicable. That gap is the extension surface, not an oversight.

---

## The enrichment block

Stage 2 attaches an `enrichment` object to every event before anything scores it. Which
labels appear depends on `source|event_type`; a label that does not apply to an event type
is absent rather than null.

| Label | Type | Applies to |
| --- | --- | --- |
| `business_hours` | boolean \| null | every event type |
| `lolbas_match` | boolean \| null | `process_create`, `image_load` |
| `hijacklibs_match` | boolean \| null | `image_load` |
| `filesec_match` | boolean \| null | `process_create`, `image_load` |
| `persistence_path_class` | enum \| null | `process_create` — `registry`, `scheduled_task`, `service`, `startup`, `file_in_startup_dir` |
| `security_tool_name` | string \| null | `process_create`, `image_load` |
| `account_type` | enum \| null | `process_create`, `network_connect` — `user`, `admin`, `service` |

Only `business_hours` is computed by athanor, from
[`data/business-hours/config.yaml`](../data/business-hours/config.yaml) (UTC, Monday to
Friday, 09:00–17:00 by default). The other labels are **carried through if an upstream tool
already set them** and left `null` otherwise. An `events.json` produced by a pipeline that
does LOLBAS matching keeps its `lolbas_match` values; a folder of raw logs will not have
them.

An event that arrives with an `enrichment` block has it normalized against the applicable
label set, then `business_hours` filled if it was `null`. Existing values are never
overwritten.

Stage 2 output is validated against a strict contract before scoring: `timestamp`, `source`
and `event_type` must be non-empty strings, `enrichment` must be an object containing only
the seven labels above. Any other shape fails the run rather than scoring on a
half-formed event.

---

## Candidate output

Not part of the event schema, but the other end of the same contract. Each emitted
candidate carries:

| Block | Contents |
| --- | --- |
| `candidate_id` | the presentation id (`BCN-001`) once presentation ids are enabled |
| `pipeline_candidate_id` | the content-derived id: `<PREFIX>-` + the first 16 hex characters of a SHA-256 over the candidate's own contents |
| `type` | `beacon`, `data_transfer`, `tls_anomaly`, `unusual_parent_child_anomaly`, `powershell_invocation_anomaly` |
| `<type>_score` | the composite, in `[0, 1]`, rounded to 4 decimals |
| feature fields | every input to that score, per type |
| `evidence.constituent_event_ids` | the ids of every event the candidate was built from |
| `attribution` | **network types only** (`beacon`, `data_transfer`, `tls_anomaly`): host, user, process identity, a `confidence` of `full` / `partial_time_skew` / `partial_multi_process` / `inferred` / `unavailable`, and `data_quality_flags` naming why. The two process types are built from EID 1 events that already carry process identity, so they have no bridge to walk and no `attribution` block |
| `enrichment` | the stage-4 labels applicable to that candidate type |

The content-derived id is computed over the candidate with its own id field removed, using
a canonical serialization (keys sorted, arrays sorted, numbers rounded to 6 decimals). Two
identical candidates from two identical runs get the same id on any machine — and a
candidate whose evidence ids shifted because a file was added to the folder gets a
different one.
