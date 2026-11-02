# Native delivery-policy backup schema qualification — 2026-11-02

Production gates: [#4](https://github.com/gigabytegrove/spamgate/issues/4), [#8](https://github.com/gigabytegrove/spamgate/issues/8).

## Failure mode

The cold-backup validator previously inspected only the `initialized` witness and top-level JSON field names. An archive with internally consistent ZIP checksums could contain invalid SHA-256 counter identities, malformed or zero timestamps, null rate arrays, or duplicate nested keys. `Verify` could certify it and `Restore` could publish it, even though the native worker's strict `readDeliveryPolicyState` would reject the restored file at startup. This was a disaster-recovery qualification defect, not an observed production outage.

## Enforced behavior

- `Create`, `Verify` and `Restore` validate the full persisted delivery-policy counter schema and initialization marker relationship.
- Counter keys must be exactly 64 lowercase hexadecimal characters. Greylist and rate timestamps must parse as nonzero RFC3339 values; rate lists cannot be null.
- The same bounds as the worker apply: 20,000 greylist keys, 20,000 rate keys, 100,000 timestamps per rate key, 200,000 rate timestamps overall and 16 MiB per state file.
- Existing strict JSON integrity checks reject ambiguous duplicate and Unicode-aliased keys, including nested keys; unknown fields and trailing documents are refused.
- Source inspection checks file identity, size and modification time before and after validation. Invalid evidence is not repaired or rewritten.
- Adversarial tests forge self-consistent ZIP manifests and assert both verification and restoration refuse unreadable state without publishing a destination; valid nonempty and legacy state remain accepted.

## Qualification limits

The checks mirror the native policy-state reader's current schema. They do not authenticate archives or constitute a real-host disaster-recovery drill. An attacker able to rewrite both archive and manifest can recompute SHA-256. Independent crash, ENOSPC, power-loss, production ISPConfig and disaster-recovery testing remain mandatory. All nine cumulative issues remain open; the October 31 beta deadline was missed.
