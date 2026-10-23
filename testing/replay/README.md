# Attack replay

Coverage is only a claim until the events fire. These tests run real attack
techniques on a disposable Windows runner and assert that the Sysmon events each
technique module depends on actually appear.

## What is (and isn't) here

- `manifest.json` — the test plan: for each priority technique, the Atomic Red
  Team test GUID, the Sysmon events that must appear, and the modules it proves.
- `Invoke-Replay.ps1` — the runner: loads a profile, runs each atomic **by GUID**
  through [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam),
  then reads the Sysmon Operational log and checks the expected event IDs appear.
- `results.json` — written by a run (committed after a CI run, like the volume
  baseline). The coverage matrix's Replay column reflects it.

**The attack commands are not in this repository.** `Invoke-AtomicTest` fetches
and runs them from the Atomic Red Team checkout pinned in `manifest.json`
(`framework.atomics_ref`). This repo only orchestrates and checks telemetry.

## Running it

CI runs it on `windows-latest` via `.github/workflows/replay.yml` (weekly, on
dispatch, and on PRs touching modules or the replay files). It uploads a report
and prints a summary.

To run on your own **disposable** Windows VM (never a machine you care about — it
disables Defender real-time protection and executes real techniques):

```powershell
./testing/replay/Invoke-Replay.ps1 -ConfigProfile balanced -OutputPath replay-report.md
```

The script exits non-zero if any technique's expected events did not fire.

## Adding a technique

1. Find a non-destructive Atomic test with cleanup for the technique.
2. Add an entry to `manifest.json`: its `technique` (the Atomic folder), `guid`,
   `name`, `elevation`, the `expect`ed Sysmon event names, and the `modules` it
   proves. The build fails if a listed module does not exist.
3. `python tools/sysmongen.py build` to refresh the coverage matrix.
4. The next replay run proves (or disproves) it.
