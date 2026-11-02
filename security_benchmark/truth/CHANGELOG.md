# Ground-truth changelog

Every change to a label after results were seen is listed here, with its
evidence. Labels added after a run was seen carry `origin: post_hoc` in the
truth file. `score` reports every metric both with them and without them
(`score.json` → `without_post_hoc`), and the paper reports both.

Origins:

| origin | meaning |
|---|---|
| `upstream` | The target's own authors document it: their tests, solutions, source comments, or README. |
| `source_audit` | We derived it from the target's source *before* seeing any tool output. |
| `post_hoc` | Added or changed *after* a tool's output was seen. It still needs upstream or source evidence. |

## 2026-10-23 — freeze before the final runs

### DVGA (`templates/ground_truth/examples/dvga/dvga.yaml`)

| Cell | Change | Origin | Evidence | Effect on the first held-out run |
|---|---|---|---|---|
| `importPaste::os_command_injection` | added | post_hoc | DVGA `tests/test_vulnerabilities.py::test_os_injection`; `core/views.py`: `run_cmd(f'curl --insecure {url}')` | Was an FP; becomes a TP. |
| `systemDebug::os_command_injection` | added | post_hoc | DVGA `core/views.py` `resolve_system_debug`: `run_cmd('ps {}'.format(arg))` → `os.popen` | Was an unlabelled confirmed finding; becomes a TP. |
| `__schema::field_suggestion` | added | post_hoc | DVGA `tests/test_vulnerabilities.py::test_field_suggestions` | Not found: adds an FN. The draft had placed it on `systemUpdate`, but it is a schema-level behaviour, keyed on `__schema` like introspection. |
| `systemDiagnostics::os_command_injection` | preconditions now include `cmd`; witness hint updated | upstream | DVGA `tests/test_vulnerabilities.py::test_os_injection_alt` | None: preconditions and hints are not scored. |

All other DVGA labels are unchanged from the committed version and are
`origin: upstream`.

### GraphQLer benchmark apps (`injection`, `idor`, `vvsm`, `api-security`)

Labels are unchanged. Each class now records `origin: upstream` and a `source`
citation. An earlier run of `truth certify` had re-emitted these files and
dropped their provenance comments. They were restored from git, and `certify`
now edits only the header fields.

### `injection-patched`

Header converted to block style so `certify` can stamp it. Its labels are all
negatives and are unchanged.
