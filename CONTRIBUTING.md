# Contributing

## Pair Workflow

| Partner   | Owns                                      | Branch prefix       |
|-----------|-------------------------------------------|---------------------|
| Partner A | `attacker/`, `victim/`, `tests/pcaps/`    | `feat/attacker-*`, `feat/victim-*` |
| Partner B | `detector/`, `tests/run_tests.sh`         | `feat/detector-*`, `feat/report-*` |

Shared files (`docker-compose.yml`, `Makefile`, `README.md`) require both partners to approve before merging.

## Branch Naming

```
feat/<area>-<short-description>   # new feature
fix/<area>-<short-description>    # bug fix
chore/<what>                      # docs, tooling, cleanup
```

## Pull Request Checklist

- [ ] `make bootstrap` runs cleanly from scratch
- [ ] `make test` passes with no regressions
- [ ] New PCAP test cases include a matching `.yaml` ground-truth file
- [ ] No real traffic captures committed to the repo

## Commit Format

```
feat(attacker): add SYN flood script
fix(detector): correct SYN/ACK threshold
test(pcaps): add 3 UDP flood labeled cases
```

## Adding a Test Case

1. Generate the PCAP using the attacker container
2. Save to `tests/pcaps/<type>_<NN>.pcap`
3. Create matching `tests/pcaps/<type>_<NN>.yaml`:

```yaml
attack_type: syn_flood      # syn_flood | udp_flood | slowloris | benign
expected_alert: true
duration_sec: 30
notes: "description of this case"
```

4. Run `make test` to confirm it passes, then open a PR
