# GraphQL security benchmark (labeled, self-hosted)

Ground-truth-labeled vulnerable GraphQL apps for the detection study (RQ3): the
false-positive-aware precision/recall evaluation the reviewers asked for. The apps
are the **GraphQLer `sample-graphql-apis`** (from the GraphQLer Zenodo artifact's
`targets/`), each with a known, source-documented set of vulnerabilities.

## Apps and ports (security profile)

| App | Port | Labeled classes (engine-detectable) | Truth file |
|---|---|---|---|
| injection-vulnerabilities-api | 4002 | sql_injection, path_traversal, os_command_injection, xss_stored | `truth/injection.yaml` |
| idor-api | 8010¹ | idor (×5 ops) + 2 negatives | `truth/idor.yaml` |
| very-vulnerable-social-media-api | 8001 | uaf (use-after-delete) + 1 negative | `truth/vvsm.yaml` |
| api-security-api | 4004 | introspection² | `truth/api-security.yaml` |

¹ remapped from 8000 → 8010 because the PrediQL dashboard also uses 8000.
² field-suggestions and alias deny-list bypass are designed into the app but have
  no deterministic engine family yet → recorded as known recall gaps, not scored
  positives (disclose in Threats-to-Validity).

## Bring the stack up

The app sources + Dockerfiles ship in the GraphQLer artifact (`targets/`). From
that `targets/` directory:

```bash
# NOTE: edit docker-compose.yml so idor-api publishes 127.0.0.1:8010:8000
docker compose --profile security up -d --build
```

All four bind to `127.0.0.1` only. Tear down with
`docker compose --profile security down`.

## Identities (for the differential IDOR/UAF oracles)

idor-api (victim/attacker — the IDOR chain needs both):
```
--identity "alice:user=Authorization: Bearer alice_token_abc123"
--identity "bob:user=Authorization: Bearer bob_token_xyz789"
```
vvsm (single identity; UAF is read-after-delete):
```
--identity "alice:user=Authorization: Bearer alice_social_token"
```

## Scoring

Certify each truth file against the live schema before scoring:
```bash
predql truth certify --truth security_benchmark/truth/injection.yaml
```
Then run the security mode with `--truth <file>` and score precision/recall/F1 on
the positives and the **false-positive rate on the negatives** (myNotes/myOrders,
myPosts). Patched/hardened negatives (S2) extend the FP measurement further.

## Provenance
Apps: GraphQLer (omar2535/GraphQLer) `sample-graphql-apis`, MIT. Labels authored
from each app's own source/README; see each truth file's `source:` field.
