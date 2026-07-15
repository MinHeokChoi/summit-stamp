# Dataset update runbook

## Current starting point

The checked-in resources are M1, an integrity-verified public-official-source
release candidate. They are not an M0 empty skeleton and are not a releasable
human-approved dataset. M1 is identified by:

- manifest and catalog status `release_candidate_public_official_source`
- legacy mapping status `release_candidate_legacy_mapping`
- manifest review status `not_human_reviewed`, empty reviewers, and null
  `reviewedAt`
- 100 official references, catalog entries, and one-to-one legacy mappings

The M1 source is the Korea Forest Service page
`https://map.forest.go.kr/forest/?systype=appdata`, GIS service
`https://map.forest.go.kr/gis1/iserver/services/data-fdms/rest/data`, table
`FDMS_BASE:TB_FGDI_FS_F100`, source CRS `EPSG:5179`, retrieved at
`2026-07-14T00:03:32.659Z`, with raw-source SHA-256
`c82eab718f45afc58bbe45d7f6a4904187fb7f0d0cd6aadd0a287ae78d13128d`.
The manifest binds that digest to the exact raw evidence resource
`Evidence/dataset/official-100-mountains-v1.raw.json` and normalized evidence
resource `Evidence/dataset/official-100-mountains-v1.normalized.json`.

The current content resource is `official-100-mountains-v1` (WGS84), SHA-256
`1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae`. The
separate legacy mapping resource is `legacy-mountain-metadata-v1`, SHA-256
`04028d8e4895eff00cdcd96267460eebb0ccaed3450c643ef06b30e1c87ffc73`.

## 1. Acquire the official source offline

Use `Scripts/dataset/fetch-official-100.py` only as an offline build-time
acquisition utility. It fetches and normalizes the Korea Forest Service GIS
snapshot for preservation and review; it is never a runtime catalog
replacement, app feature, background refresh, or fallback when bundled data is
missing.

For an acquisition, record the UTC time and preserve both review artifacts at
the manifest-declared, non-runtime paths:

```sh
python3 Scripts/dataset/fetch-official-100.py \
  --raw-output Evidence/dataset/official-100-mountains-v1.raw.json \
  --output Evidence/dataset/official-100-mountains-v1.normalized.json \
  --retrieved-at 2026-07-14T00:03:32.659Z
```

The utility atomically writes the exact response bytes to `--raw-output`, then
writes `--output` only after strict normalization succeeds. Set
`source.rawResource` to the raw path, `source.normalizedSnapshotPath` to the
normalized path, and `source.sha256` to the SHA-256 of the exact raw bytes.
The normalized artifact's `source.rawSHA256` must equal that manifest digest;
its canonical `recordsSHA256` must match its records. It rejects HTTP redirects,
responses over 10 MiB, invalid UTF-8/JSON, duplicate keys, and nonstandard JSON
constants. The verified service encodes official IDs and elevations as canonical
decimal strings: IDs must be exactly `1` through `100`; elevations must be
finite canonical decimals. Administrative codes must be eight ASCII digits, and
coordinates must be finite. Do not substitute an aggregator, a search result, a
screen scrape, a hash copied from a web page, or a runtime HTTP request.

## 2. Build candidate resources

1. Preserve the raw and normalized official evidence before changing the
   bundled resources. Do not put either artifact in the runtime resource bundle.
2. Update the catalog and legacy mapping from the normalized official records.
   The catalog uses each source record's WGS84 representative point; the source
   record retains `EPSG:5179` as the official source CRS.
3. Keep exactly 100 entries in ascending official source-reference order `1`
   through `100`. Each `sourceReference` must be the matching normalized
   `officialMountainID`.
4. Derive every current app ID deterministically as the first 32 lowercase hex
   characters of SHA-256 of `kfs:FDMS_BASE:TB_FGDI_FS_F100:<sourceReference>`,
   prefixed with `hkr_mtn_`. Do not generate IDs from names, ranks, coordinates,
   or legacy values.
5. Keep the legacy mapping ordered by the same references and one-to-one with
   catalog IDs. Reject duplicate or missing legacy IDs, current IDs, or catalog
   IDs rather than filling gaps.
6. Copy each normalized official name, administrative code (and therefore its
   broad-region derivation), longitude, and latitude exactly to its matching
   catalog record. Do not infer or correct those values from other sources.
7. Calculate the exact-byte SHA-256 of each checked-in bundled resource
   separately and write each resource name and checksum to its own manifest
   provenance object. Do not use a combined checksum.
8. Keep M1 review provenance as `not_human_reviewed`, an empty reviewer array,
   and null `reviewedAt`. Never invent a reviewer, approval, or signing claim
   to move a candidate through a gate.

Candidate validation is the required integrity check:

```sh
python3 Scripts/dataset/validate-manifest.py --mode candidate
```

A failure for missing or substituted raw/normalized source evidence, a raw or
normalized-records digest mismatch, unknown JSON fields, duplicate keys,
source-reference order, catalog/source name, code, region, or coordinate drift,
ID derivation, or count is a candidate blocker. Fix the source artifact or
provenance record; do not loosen the validator and do not replace bundled data
at runtime.

## 3. Perform independent Data Steward review

Two distinct Data Stewards independently inspect the preserved raw official
bytes, normalized snapshot, and candidate resources. Each verifies:

- the raw-resource SHA-256 equals `source.sha256` and the normalized
  `source.rawSHA256`;
- official source page, service, endpoint, table, query, CRS, and timestamp;
- catalog and legacy resource names and exact-byte checksums;
- all 100 normalized references, deterministic opaque IDs, legacy mappings,
  and order;
- names, WGS84 representative coordinates, administrative codes, and
  broad-region derivation;
- the intended dataset version and release scope.

The review/signing boundary is strict: candidate integrity validation and an
app signing certificate do not constitute human approval. A Data Steward who
collected the snapshot or changed the mapping cannot be the sole reviewer.
Only after both independent reviews are complete may the manifest make an
approval claim.
Each approval timestamp must be at or after the source retrieval timestamp, and
the manifest `reviewedAt` must be at or after every individual approval.

## 4. Record approval and validate release

For a true release, use a non-prerelease semantic dataset version; promote the
manifest, catalog, and legacy resource statuses to `approved`; recalculate
resource checksums after the approved resource bytes are finalized; and record
the release provenance. Add at least two distinct reviewer objects. Each must
state a stable reviewer ID, role `Data Steward`, decision `approved`, and a UTC
review timestamp. Set a UTC manifest `reviewedAt` only after those reviews are
complete.

Then run:

```sh
python3 Scripts/dataset/validate-manifest.py --mode release
```

The current M1 candidate must fail this command because its review provenance is
`not_human_reviewed`; that failure is the intended release gate. Release mode
also fails closed without two distinct Data Steward approvals, a non-prerelease
version, valid chronological approval timestamps, approved statuses, valid
resource hashes, and all catalog/mapping invariants. Do not change status or
add reviewer records merely to make this command pass.

## 5. Package and retain the release record

After release validation succeeds, ship the reviewed resources only inside a
newly signed application build. Record the application version, dataset version,
source hash, separate content and legacy hashes, both Data Steward identities,
and validation result with the release materials.

Do not distribute a catalog alteration through remote configuration, a backend
response, a remote manifest, a crosswalk service, or a silent download. A
factual correction repeats this runbook and ships in a new signed app update;
it never mutates an already-shipped catalog in place.

`--mode skeleton` remains available solely for validating a historical M0 empty
skeleton. It is not the validation mode or current state for the checked-in M1
resources.
