# ssm-value-sweeper

**Hunt a rotated secret by its value, not by its key name.**

A relay key rotated. The app still calls the old endpoint. Everyone greps
Parameter Store for parameter *names* that look relevant — and still loses,
because in any real estate over 500 parameters, some secret is hiding under an
innocent name. (Recent real case: a rotated relay API key whose last surviving
copy lived in a parameter named `SLACK_URL_KEY`. Name-based search found
nothing. A value-hash sweep found every copy.)

This tool hashes each parameter's **decrypted value** and compares against the
rotated secret, across any number of AWS accounts.

## What it does

| Subcommand | Purpose |
|---|---|
| `snapshot` | name + type + `sha256` inventory of every parameter (plaintext never written to the report) |
| `find` | given a rotated secret (file / string / hash), report parameters whose value **matches exactly** or (with `--substring`) **contains** it |
| `diff` | diff two snapshots — added / removed / **value-changed** parameter names |

## Quickstart

```bash
pip install boto3            # aws cli creds/profiles already configured

# inventory your estate (three accounts in this example)
python -m ssm_value_sweeper.cli snapshot --profiles prod-a,prod-b,prod-c

# the day you rotate a key: did every copy die?
echo -n "$OLD_SECRET" > /tmp/old-secret.txt
python -m ssm_value_sweeper.cli find \
    --profiles prod-a,prod-b,prod-c \
    --file /tmp/old-secret.txt \
    --substring
rm -f /tmp/old-secret.txt        # purge the moment it's done
```

Exit code: `0` when a copy still lives (get cleaning), `1` when clean.

Hash-only mode (when you no longer hold the plaintext but have a hash):

```bash
python -m ssm_value_sweeper.cli find --profiles prod-a --hash bbca21a139ad8887...
```

Diff before/after a migration:

```bash
python -m ssm_value_sweeper.cli diff snapshot-prod-a.json snapshot-prod-c.json
```

## Why value-based searching

- **Names lie.** Environments accumulate params whose names reflect who
  created them, not what they carry.
- **Identical secrets, different wrappers.** The same key embedded in a
  webhook URL, quoted, or with a stray trailing newline is invisible to
  exact-match grep — but consistent after normalization.
- **Rotation is a set of copies, not one value.** The report is only honest
  if it scans *everything* and reports *every* copy.

## Trailing-newline normalization (the silent false alarm)

Secret material copied through editors and
shell heredocs routinely gains a trailing `\n`. Hashing with it produces a
different digest than AWS's stored value, and a sweep reports "clean" when it
is not. This tool strips trailing `\r\n` before hashing, always.

## Safety notes

- Values are decrypted in memory, hashed, and discarded; reports contain
  names and hashes only — unless you explicitly pass `--store-values`
  (which warns loudly on every parameter).
- Run `find --file ...` on a throwaway file and delete it right after; the
  tool does not delete it for you.
- `--string` leaks into shell history; prefer `--file`.
- Substring mode (`--substring`) requires holding the plaintext secret — it
  cannot work from a hash alone.

## Field notes from real incidents

- Sweep **all** parameters, not the ones you "know" are relevant. The whole
  point is that you don't know.
- Sweep **both accounts** whenever two estates share infrastructure through a
  migration (parameter stores that "must not" have the key still do).
- Verify the fix by reading back: `snapshot` again, `diff` the run, confirm
  `changed` contains exactly the parameters you intended to PUT.
- Consumers external to the parameter store (k8s Secrets via External
  Secrets Operator, CI caches) are out of scope here — verify those
  separately (see `eso-drift-guard`).

## Sample session output

```text
MATCH [prod-b] /sandbox/RELAY_API_KEY          (substring-of-value)
MATCH [prod-b] /integrations/RELAY/endpoint     (exact-value)

Scanned 2550 parameter(s). Matches: 2
Report -> find-report.json
```

## Limitations

- SecureString values are obtained via `WithDecryption=True`; the calling
  principal needs `ssm:GetParameter` and the KMS keys.
- `SecureString` params carrying binary blobs are hashed from their decoded
  text rendering; exotic encodings may need attention.
- `--hash` mode does exact-hash matching only — it cannot test whether the
  plaintext appears embedded inside an URL (`--substring` requires the
  plaintext).

## License

MIT — see [LICENSE](LICENSE).
