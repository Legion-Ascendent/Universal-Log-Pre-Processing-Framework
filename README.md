# ULPF — Universal Log Pre-Processing Framework

ULPF takes security/network logs in **any format** — Syslog, JSON, CEF, or
something nobody's written a parser for yet — and turns them into **one
consistent, searchable record**, with every normalized event traceable
back to the exact original line it came from. It runs entirely offline,
starts with a single Docker command, and includes a live-updating
dashboard.

---

## What this project actually does (in plain terms)

Most security teams pull logs from many different devices — firewalls,
proxies, cloud gateways — and every vendor logs things differently. One
device writes plain-text Syslog, another writes JSON, another writes CEF,
and some write something entirely proprietary. Normally that means either
writing a separate parser for every single format, or losing visibility
into whatever isn't supported yet.

ULPF solves this with one pipeline that treats every log line the same
way, no matter what format it arrived in:

1. **Save the raw line first, no matter what.** This happens before
   anything else is even attempted, and nothing downstream can undo it —
   so no log line is ever silently lost, even if it later turns out to be
   unparseable.
2. **Figure out what format it's in.** JSON, CEF, and Syslog are each
   detected by their own distinctive shape.
3. **Hand it to the matching parser** — a dedicated one for each known
   format, or, if the format isn't recognized at all, an automatic
   fallback (see below) that still makes sense of it.
4. **Normalize it** into one shared shape, so every event — regardless of
   its original format — ends up with the same fields (timestamp, source
   IP, action taken, severity, etc.), using the same fixed vocabulary.
5. **Store it, linked back to the original raw line**, and make it
   available on the dashboard.

The one genuinely novel piece: when ULPF sees a log format it has no
parser for, it doesn't drop it. It runs the line through Drain3 (a
log-template-mining algorithm) to automatically learn the line's
structure — which parts are fixed text and which parts are data — and
pulls out what it can (IPs, ports, a small action vocabulary), entirely
without being told the format's schema in advance.

---

## Quick start — the easy way (Docker, no local Python needed)

This is the fastest way to actually see it running.

```bash
# 1. Get the code
git clone https://github.com/Legion-Ascendent/Universal-Log-Pre-Processing-Framework
cd Universal-Log-Pre-Processing-Framework

# 2. Build and start the dashboard (one command, does everything)
docker compose up --build -d

# 3. Load the sample logs into the database (one-time)
docker compose exec dashboard python3 pipeline.py

# 4. Open your browser to:
#    http://localhost:8501
```

That's it — you now have a working dashboard showing normalized events
across every log format, filterable, with click-through traceability back
to the original raw lines.

> **If `docker compose` doesn't work:** some older Docker installs only
> have the standalone `docker-compose` (with a hyphen) instead of the
> newer `docker compose` (with a space, built into Docker itself). Try
> whichever one your install has.

Everything here works with **zero internet access** once the image is
built — no live API calls anywhere, including the enrichment features
below. You can disconnect your network entirely after step 2 and it'll
keep working.

---

## Quick start — for development (running Python directly)

Use this instead of Docker if you want to edit code and see changes
immediately.

```bash
git clone https://github.com/Legion-Ascendent/Universal-Log-Pre-Processing-Framework
cd Universal-Log-Pre-Processing-Framework

# Create an isolated Python environment so this project's dependencies
# don't clash with anything else on your machine
python -m venv .venv

# Activate it:
#   Windows (PowerShell):
.venv\Scripts\Activate.ps1
#   macOS/Linux:
source .venv/bin/activate

# Install everything this project needs
pip install -r requirements.txt

# Load the sample logs into the database
python3 pipeline.py

# Start the dashboard
streamlit run dashboard/app.py
#   -> opens automatically at http://localhost:8501
```

---

## The two ways to get logs into the system

### 1. Batch mode — `pipeline.py` (the default)

Reads every `.log` file currently sitting in `sample_logs/`, processes
every line once, then stops. This is the normal way to load data:

```bash
python3 pipeline.py
```

To load new data later, add or edit files in `sample_logs/`, then run
this command again. It's simple and predictable, but it's a one-time
pass — nothing happens automatically while it isn't running, and running
it twice against the same files will process those lines twice (see
Known Limitations).

### 2. Live mode — `live_demo_watch.py` (for live demos)

`pipeline.py`'s ingestion step only ever does a single batch read — it
was never meant to run continuously. `live_demo_watch.py` fills that gap:
it keeps running in the background, checking `sample_logs/` every couple
of seconds, and picks up **only genuinely new content** — a brand-new
`.log` file, or new lines appended to a file it's already seen — without
you restarting anything.

```bash
python3 live_demo_watch.py
```

This is built specifically for demoing the pipeline live: start it
running, then in a separate window either create a new `.log` file in
`sample_logs/` or append a line to an existing one, and watch the event
appear on the dashboard within a couple of seconds — no restart needed.

Every line it finds goes through the **exact same** `process_one_line()`
function that `pipeline.py`'s batch mode uses — there's no separate
parsing logic here, so a line is treated identically no matter which
mode picked it up. It only processes content that's genuinely new since
it started (existing content already in `sample_logs/` when you launch it
is treated as already-seen, not reprocessed) — so the intended flow is:
run `pipeline.py` once first to load your starting data, *then* start
`live_demo_watch.py` to demonstrate new data arriving live on top of
that. Press `Ctrl+C` to stop it.

---

## What you'll see on the dashboard

- Every normalized event, across every log format, in one table.
- Filters: source format, action (allow/deny/alert/drop), and exact IP match.
- A live count: *"X events across Y source formats"* — proof everything
  really is unified, not siloed by format.
- A live count of how many events came through a known-format parser vs.
  the Drain3 automatic-discovery fallback.
- **Country** and **Known Bad IP** columns for each event's source IP
  (see Enrichment below).
- Click any row to see its full normalized data **and** the original raw
  log line it came from, side by side — full traceability, every time.

---

## Enrichment (optional add-ons)

Two small, fully offline modules that add context to each event, both
shown live on the dashboard:

- **GeoIP lookup** (`enrichment/geoip_lookup.py`) — tags an IP with a
  country, using a small hand-made CSV
  (`enrichment/ip_ranges.csv`) covering this project's own sample data.
  Not a real-world GeoIP database.
- **Threat-intel lookup** (`enrichment/threat_intel_lookup.py`) — flags
  an IP against a small hardcoded "known bad" list. A demo simulation,
  not a real threat feed.

Both are computed live, when the dashboard loads — nothing is stored in
the database, so updating either file changes what the dashboard shows
immediately, without needing to reprocess old events.

---

## Project structure

```
├── docker-compose.yml         # one-command startup
├── Dockerfile
├── requirements.txt           # streamlit, drain3, pandas
├── conftest.py                # lets `pytest tests/` find repo-root packages
├── README.md
│
├── sample_logs/                # your input logs live here (one file per format, plus a mixed file)
├── data/                        # created automatically at runtime (gitignored) — the database lives here
│
├── shared/contracts.py           # the single shared "rulebook" every module agrees on
├── storage/                       # saves and reads both raw and normalized events (SQLite)
├── ingestion/                      # reads log files from sample_logs/
├── detector/                        # figures out which format a line is in
├── parsers/                          # one normalizer per known format (Syslog/JSON/CEF), + the Drain3 fallback
├── enrichment/                        # optional: GeoIP + threat-intel tagging
├── dashboard/app.py                    # the web dashboard (Streamlit)
│
├── pipeline.py                          # runs everything, once (batch mode)
├── live_demo_watch.py                    # runs everything, continuously (live mode)
└── tests/                                 # automated tests
```

## What you need installed

- **Docker + Docker Compose** (recommended path) — nothing else needed;
  Python and all dependencies live inside the container.
- **OR, for local development:** Python 3.11 or newer, plus everything in
  `requirements.txt` (installed automatically via `pip install -r
  requirements.txt` above).

## Running the automated tests

```bash
pytest tests/
```

## Known limitations

- **Batch mode (`pipeline.py`) duplicates data if you run it twice**
  against the same log files — there's no de-duplication by content.
  Live mode (`live_demo_watch.py`) avoids this for its own workflow,
  since it only ever looks at content that's new since it started.
- The built-in action vocabulary (allow/deny/alert/drop) is intentionally
  narrow. Events that aren't firewall-style decisions — a login attempt, a
  file being read, an application error — may correctly show
  `action: unknown` rather than being forced into a category that doesn't
  really describe them.
- GeoIP and threat-intel enrichment only cover IPs actually present in
  this project's own sample data, not real-world IP ranges.
