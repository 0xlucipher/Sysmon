# Probes

Deliberately invalid configurations. CI loads each one into real Sysmon and
reports whether Sysmon rejects it. This records Sysmon's actual behaviour for
each mistake `tools/sysmonlint.py` flags, and shows the load test can detect a
rejection. Probes are informational and never fail the build.
