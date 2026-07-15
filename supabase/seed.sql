-- Local deterministic reference scaffold only. This is not a product dataset and
-- must never be promoted, exported, or used as release evidence.
BEGIN;

WITH fixture_manifest AS (
    SELECT
        'hiker-test-v1'::text AS dataset_version,
        1 AS schema_version,
        'https://example.invalid/hiker/local-test-reference-v1'::text AS source_url,
        '{"datasetVersion":"hiker-test-v1","mountainCount":2,"purpose":"local-test-reference-scaffold","schemaVersion":1}'::text AS manifest_body,
        E'fixture-north|37.500000|127.000000\nfixture-south|35.100000|129.000000\n'::text AS source_body,
        2 AS mountain_count,
        timestamptz '2000-01-01 00:00:00+00' AS released_at
)
INSERT INTO public.dataset_manifests (
    dataset_version,
    schema_version,
    manifest_sha256,
    source_url,
    source_sha256,
    mountain_count,
    released_at
)
SELECT
    dataset_version,
    schema_version,
    encode(extensions.digest(manifest_body, 'sha256'), 'hex'),
    source_url,
    encode(extensions.digest(source_body, 'sha256'), 'hex'),
    mountain_count,
    released_at
FROM fixture_manifest
ON CONFLICT (dataset_version) DO NOTHING;

INSERT INTO public.mountains (
    mountain_id,
    dataset_version,
    source_identifier,
    display_name,
    region,
    latitude,
    longitude
)
VALUES
    (
        '11111111-1111-4111-8111-111111111111',
        'hiker-test-v1',
        'fixture-north',
        'Fixture Peak North',
        'Fixture Region',
        37.500000,
        127.000000
    ),
    (
        '22222222-2222-4222-8222-222222222222',
        'hiker-test-v1',
        'fixture-south',
        'Fixture Peak South',
        'Fixture Region',
        35.100000,
        129.000000
    )
ON CONFLICT (dataset_version, mountain_id) DO NOTHING;

COMMIT;
