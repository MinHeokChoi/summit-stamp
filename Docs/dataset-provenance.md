# Dataset provenance policy

## Current state: M1 public-official-source release candidate

The checked-in dataset is an integrity-verified **M1 release candidate**, not an
approved release. Its manifest is
`Packages/HikerDataset/Sources/HikerDataset/Resources/dataset-manifest.json` and
its status is `release_candidate_public_official_source`.

The M1 source record is fixed to the Korea Forest Service public GIS record and
to two checked-in, non-runtime evidence resources:

- source page: `https://map.forest.go.kr/forest/?systype=appdata`
- service: `https://map.forest.go.kr/gis1/iserver/services/data-fdms/rest/data`
- table: `FDMS_BASE:TB_FGDI_FS_F100`
- source CRS: `EPSG:5179`
- retrieved at: `2026-07-14T00:03:32.659Z`
- raw resource: `Evidence/dataset/official-100-mountains-v1.raw.json`
- normalized resource:
  `Evidence/dataset/official-100-mountains-v1.normalized.json`
- raw-source SHA-256:
  `c82eab718f45afc58bbe45d7f6a4904187fb7f0d0cd6aadd0a287ae78d13128d`

`source.rawResource` and `source.normalizedSnapshotPath` are repository-relative
paths. `source.sha256` hashes the exact raw-resource bytes. The candidate
validator hashes that raw resource, requires the normalized artifact's
`source.rawSHA256` to equal it, and then verifies the normalized records before
deriving catalog fields.

M1 has no human approval claim. Its review provenance is exactly
`not_human_reviewed`, with an empty reviewer list and a null `reviewedAt`.
This is factual provenance: a successful candidate validation proves bundled
resource integrity and contract conformance, not human review or release
approval.

Validate the checked-in candidate with:

```sh
python3 Scripts/dataset/validate-manifest.py --mode candidate
```

## Bundled resources and identity contract

The manifest identifies two distinct bundled resources. Their SHA-256 values
are hashes of the exact checked-in resource bytes, not hashes copied from a web
page or of a normalized subset:

- content resource `official-100-mountains-v1` (WGS84):
  `1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae`
- legacy mapping resource `legacy-mountain-metadata-v1`:
  `04028d8e4895eff00cdcd96267460eebb0ccaed3450c643ef06b30e1c87ffc73`

M1 contains exactly 100 catalog entries and 100 legacy mappings. Catalog
entries are in ascending official reference order `1` through `100`. Each app
ID is opaque but deterministic for this source table:

```text
hkr_mtn_<first 32 lowercase hex characters of SHA-256(
  "kfs:FDMS_BASE:TB_FGDI_FS_F100:<sourceReference>"
)>
```

The catalog and legacy mapping must both use that derivation for every
reference, contain no duplicate or missing IDs, and map one-to-one. IDs are not
derived from a mountain name, coordinate, rank, or a legacy ID. They remain
stable across factual corrections; source references and legacy IDs remain
provenance data.

Coordinates are WGS84 representative points and must be finite values within
the South Korea bounds used by the acquisition workflow. Catalog-to-normalized
coordinate binding permits an absolute difference of at most `1e-7` degrees for
each finite longitude and latitude. This accommodates the observed
sub-centimeter projection serialization jitter while rejecting material
coordinate drift. Each entry has an 8-ASCII-digit administrative code. The
application derives its broad region from the code's first two digits; the
supported prefixes are the Korean administrative regions represented by the
bundled data. An unknown, malformed, or unsupported code is invalid rather
than a reason to infer a region from the mountain name or coordinates.

The candidate validator hashes the declared raw resource, requires that digest
in the normalized snapshot, recomputes the normalized-records SHA-256, and
requires exactly the official IDs `1` through `100` in order. It derives every
catalog row's source reference, name, administrative code and broad-region
derivation, longitude, and latitude from its corresponding normalized record.
It also rejects source-artifact substitution, checksum mismatches, duplicate or
missing IDs, non-deterministic IDs, malformed provenance, unsupported fields,
duplicate JSON keys, nonstandard JSON constants, and invalid UTF-8 JSON.

## Validation modes

`Scripts/dataset/validate-manifest.py` deliberately distinguishes three states:

- `--mode skeleton` validates the historical M0 empty provenance skeleton. M0
  has `candidate_unapproved` status, null provenance hashes, and no entries. It
  is retained only to validate a genuine M0 artifact; it is not the checked-in
  dataset state.
- `--mode candidate` validates the current M1 public-official-source candidate.
  It requires the fixed M1 provenance, declared raw and normalized source
  evidence, the two exact bundled resources, and explicitly rejects any review
  or approval claim.
- `--mode release` validates a true approved release. It requires a
  non-prerelease semantic dataset version, approved manifest/resource statuses,
  the raw/normalized source binding, actual resource checksums, all catalog and
  legacy invariants, and two distinct Data Steward approval records. The current
  M1 manifest must fail this mode because it is `not_human_reviewed`.

A release reviewer record has exactly these facts: a stable reviewer ID, role
`Data Steward`, decision `approved`, and a UTC review timestamp. Release mode
requires at least two distinct reviewer IDs plus a UTC release `reviewedAt`.
Every Data Steward approval must be at or after source retrieval, and the
manifest `reviewedAt` must be at or after every approval. The validator can
establish that the required records are present and coherent; only the Data
Stewards can truthfully make those records after independent review.

## Acquisition, review, and distribution boundary

`Scripts/dataset/fetch-official-100.py` is an offline build-time acquisition
utility. It requires distinct `--raw-output` and `--output` paths outside the
runtime bundle, atomically preserves the exact raw response, and writes the
normalized output only after validation. For M1, retain the verified files at
the manifest-declared paths
`Evidence/dataset/official-100-mountains-v1.raw.json` and
`Evidence/dataset/official-100-mountains-v1.normalized.json`; they are evidence
inputs and are never application resources.

The normalized artifact must be the UTF-8 JSON output schema of that utility:
root `schemaVersion` `1`, source metadata, `recordCount`, `recordsSHA256`, and
the 100 normalized records. Its `source.rawSHA256` must equal the SHA-256 of
the retained raw file and the manifest's `source.sha256`; its `recordsSHA256`
is the canonical UTF-8 JSON hash of `records` with sorted keys and compact
separators. The normalized source metadata binds the endpoint, table, query,
retrieval time, source CRS `EPSG:5179`, and target CRS `EPSG:4326`. The utility
rejects redirects, responses over 10 MiB, invalid UTF-8/JSON, duplicate keys,
and nonstandard JSON constants. The verified source encodes IDs `1` through
`100` and finite elevations as canonical decimal strings; coordinates must be
finite and administrative codes must be eight ASCII digits. It is not shipped
with the app and is never a runtime catalog refresh or replacement. The app
consumes only the catalog and legacy mapping bundled in the signed application.

Before an M1 candidate is promoted, two independent Data Stewards must compare
the preserved official-source bytes, source hash, catalog checksum, legacy
checksum, deterministic ID mapping, count, coordinates, administrative-code
region derivation, and intended dataset version. A Data Steward who collected
or changed the crosswalk cannot be the only reviewer. Do not add reviewer
records, an approval status, or a signing statement before those checks occur.

A signed build does not replace Data Steward review. After review is factually
recorded, release-mode validation is the build-time gate and the reviewed
resources are distributed only in a newly signed app update. There is no remote
manifest, runtime source lookup, server-provided catalog, remote crosswalk, or
silent content download. Source URLs are audit evidence, not runtime trust
inputs.
