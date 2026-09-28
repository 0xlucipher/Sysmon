# Modules

Each module is one Sysmon event filter, stored as a complete (loadable)
Sysmon config so CI can load it on its own. Profiles in `../profiles/`
pick modules. `tools/sysmongen.py` merges them into `../dist/`.

```
modules/<event>/<name>.xml      e.g. modules/process_access/t1003_credential_dumping.xml
```

The module ID is the path without `.xml`, e.g. `process_access/t1003_credential_dumping`.

## Format

```xml
<Sysmon schemaversion="4.90">
  <!--
    title: LSASS access with credential-dumping access masks
    techniques: T1003.001
    volume: low
    source: original
    notes: optional free text
  -->
  <EventFiltering>
    <RuleGroup name="process_access/t1003_credential_dumping" groupRelation="or">
      <ProcessAccess onmatch="include">
        ...
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Rules:

- Exactly **one** RuleGroup holding **one** event filter.
- The first comment inside `<Sysmon>` is metadata (`key: value` lines). `title` is
  required. `techniques`, `sigma` and `atomics` are comma-separated lists.
- `techniques` must be current ATT&CK IDs (see `data/attack.json`). A revoked ID
  fails the build and names its replacement, e.g. `T1562.001` → `T1685`.
- `sigma` lists SigmaHQ rule IDs (see `data/sigma.json`). Each rule must read a log
  source this module's event produces, e.g. `process_creation` for ProcessCreate.
  Only include modules list Sigma rules.
- `min_schema` (4.90 or 4.91) stops a profile targeting an older schema from using it.
- `source` is `original`, or the project a rule was borrowed from, with its licence.
- Include rules get a RuleName stamped at build time
  (`technique_id=<id>,module=<module id>` when the module has one technique),
  so every event says which module matched it.

## How profiles use a module

A profile sets a mode for every event:

| Mode | Emitted as | Include modules | Exclude modules |
|---|---|---|---|
| `off` | empty include (log nothing) | skipped | skipped |
| `all` | exclude filter (log everything else) | skipped: they would narrow "all" down to "matches only" | applied |
| `selective` | include filter + exclude filter | applied | applied as exceptions |

Sysmon applies excludes before includes, so an exclude module filters every
include module for that event. Keep exclusions narrow:

- Anchor paths with `begin with` a directory users can't write to.
- Never exclude on `CommandLine` or `ParentImage` alone.

`tools/sysmonlint.py` warns about both.

## Naming

| Prefix | Meaning |
|---|---|
| `t<id>_…` | Rules for one ATT&CK technique (or a few closely related ones), e.g. `t1003_001_lsass_any` |
| `general_…` | Useful rules that span several techniques; the reason is in the title |
| `baseline_exclude` | Exclusions migrated from the original `sysmon-base.xml` |
| `dc_…` | Domain-controller rules (`dc` profile) |
| `noise_…` | Known-benign activity, for `all`-mode events |
