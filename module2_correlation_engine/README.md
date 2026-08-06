# Module 2 — Event Correlation Engine

AXERONIX XDR Copilot · the "brain" module. Turns raw normalized log
events (Module 1's output) into a small number of labeled, explainable
incidents.

## Quick start

```bash
python demo.py                                  # see it work end-to-end
python -m unittest discover correlation_engine/tests -v   # run tests
```

No dependencies beyond the Python standard library. `redis` is
optional — `store.py` falls back to an in-memory dict automatically if
`redis` isn't installed or no server is reachable, so the whole module
runs standalone with nothing else set up.

## How the code maps to the build guide

| Doc step | File | What it does |
|---|---|---|
| 1. Time-window grouping | `sessions.py` | group events by host+user within a 5-min window |
| 2. Deduplication | `dedup.py` | collapse repeats of the same alert into one, with a count |
| 3. Hand-authored rules | `rules.py` | 4 per-session rules + 1 cross-session rule, each an explicit if-this-then-that |
| 4. Alert grouping | `grouping.py` | union-find merge of alerts sharing a host/user within a time window |
| 5. Session creation | `sessions.py` (`Session`) | formalized session object — host, user, start/end, events |
| 6. Kill-chain generation | `killchain.py` | lookup-table mapping of events to kill-chain stage + MITRE technique |

`engine.py`'s `CorrelationEngine` wires all six together. `schema.py`
holds the shared data model (`Event`, `Alert`, `Session`, `Incident`)
so every stage passes the same objects around — this is the "agree on
the schema in writing" ground rule from the doc, done in code.

## The 4 rules implemented (Step 3)

1. **Brute force → success** — 3+ failed logons (`4625`) followed by a
   success (`4624`) on the same host/user.
2. **Office spawns scripting interpreter** — e.g. `WINWORD.EXE` →
   `powershell.exe` (phishing payload pattern).
3. **New account → admin group** — account creation (`4720`) followed
   by admin-group membership (`4732`) within 30 minutes.
4. **New-location logon → execution** — a logon flagged as a new
   geography for that user, followed by process execution within 15
   minutes.
5. **Lateral movement** *(cross-session)* — the same user logging into
   3+ distinct hosts within a 20-minute window.

All five are plain Python `if`/comparison logic — no ML, per the
"explainable over clever" ground rule. Each `Alert` carries the exact
source `Event`s that triggered it, so the evidence trail is always
visible (`incident.to_dict()["alerts"][i]["evidence"]`).

## Expected output (matches the doc's own example)

Feed the engine a simulated attack — failed logins, then a successful
login, then Word spawning PowerShell, then a new admin account — and
`demo.py` shows it collapsing into **one** `Incident` with 4 alerts and
a full kill-chain, not four disconnected alerts. A 40-event port scan
in the same run produces zero incidents (nothing it does matches a
rule), demonstrating dedup/rules are actually filtering noise rather
than just relabeling everything.

## Integration with Module 7 (Attack Graph)

Module 7's real code (`engine/adapter.py`) expects a different shape than
this engine's native `Incident.to_dict()` — a flat `events[]` list with
Module 7's own `event_type` vocabulary (`logon_failed`, `process_create`,
...), plus a separate Module 6-style `timeline` with `seq` numbers. This was
confirmed by reading their actual adapter code and mocks, not guessed.

`correlation_engine/module7_export.py` translates our output into that exact
shape:

```python
from correlation_engine.module7_export import to_module7_input

incident_dict, timeline_dict = to_module7_input(incident)
```

`export_to_module7.py` writes these as file pairs named the same way their
own `mocks/` fixtures are (`incident_<name>.json` +
`incident_<name>_timeline.json`), so they can be dropped straight into
Module 7's `mocks/` folder and picked up by their `data_source.py` with zero
changes on their side:

```bash
python export_to_module7.py                    # built-in sample attack
python export_to_module7.py your_logs.json      # your own logs
```

This was tested against Module 7's actual `engine/adapter.py` and
`engine/data_source.py` (not a mock of them) — `adapter.build(incident,
timeline)` runs cleanly on our exported output and produces a valid node/edge
graph, and `data_source.available_incidents()` picks our files up alongside
their own fixtures with no errors or warnings.

**What the adapter maps:**
- Windows/Sysmon `event_id` codes (`4625`, `4624`, `1`, ...) → Module 7's
  `event_type` strings (`logon_failed`, `logon_success`, `process_create`)
- Our kill-chain stage labels (`"Initial Access"`) → MITRE-style snake_case
  slugs (`initial_access`), matching their mock convention
- A unique `event_id` per event instance (Module 7 needs one per event; our
  internal `Event.event_id` holds the *type* code, which repeats across
  events by design)
- `event.extra` fields (e.g. `parent_process`, `src_ip`) → the specific
  extra fields each `event_type` needs, per their rule table in `rules.py`

Event types with no Module 7 rule yet (`account_created`,
`group_membership_changed`) still export — their `adapter.py` logs and skips
unknown types rather than erroring, so nothing is silently dropped on our
side either.

## Extending it

- **New rule:** subclass `Rule` in `rules.py`, implement `evaluate(session) -> list[Alert]`,
  add an instance to `DEFAULT_RULES`.
- **New kill-chain mapping:** add an entry to `_EVENT_ID_STAGES` or
  `_PROCESS_STAGES` in `killchain.py`.
- **Real event feed:** anything that produces `Event` objects (or JSON
  matching Module 1's schema, deserialized into `Event`) can be passed
  straight into `CorrelationEngine.run()`.
- **Real Redis:** `IncidentStore(redis_url="redis://localhost:6379/0")`
  — falls back to memory automatically if that fails to connect.

## Common pitfalls this implementation already avoids

- Rules run **before** kill-chain mapping, never the reverse (Step 6
  explicitly depends on stable grouping).
- The grouping window defaults to 1 hour, not "all time" — avoids
  merging unrelated activity into false incidents.
- Dedup runs on **alerts**, not raw events, so legitimate repeated
  events (e.g. two different real login sessions) aren't silently
  thrown away.
