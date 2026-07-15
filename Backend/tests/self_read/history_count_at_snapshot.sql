-- Local deterministic fixture only. It verifies that a completed history stream
-- contains the same number of visits as its bootstrap aggregate snapshot.
BEGIN;
-- Test-local grant for internal primitive coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;

SELECT plan(4);

CREATE OR REPLACE FUNCTION pg_temp.set_m3_fixture_claims(p_actor uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor::text,
            'iss', 'https://issuer.invalid/m3-history-count',
            'aud', 'authenticated',
            'iat', extract(epoch FROM clock_timestamp())::bigint,
            'role', 'authenticated',
            'app_metadata', jsonb_build_object('provider', 'apple')
        )::text,
        true
    );
    PERFORM set_config('request.jwt.claim.sub', p_actor::text, true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    RETURN true;
END;
$function$;

CREATE TEMP TABLE pg_temp.history_count_snapshot (
    label text PRIMARY KEY,
    response jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.history_count_snapshot TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-history-count', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-history-count-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('e', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;

SET LOCAL ROLE authenticated;

SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000201',
    timestamptz '2026-05-01 00:00:00+00',
    '00000000-0000-4000-8000-000000001201'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000202',
    timestamptz '2026-05-02 00:00:00+00',
    '00000000-0000-4000-8000-000000001202'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000203',
    timestamptz '2026-05-03 00:00:00+00',
    '00000000-0000-4000-8000-000000001203'
);

INSERT INTO pg_temp.history_count_snapshot (label, response)
SELECT 'bootstrap', public.m3_self_bootstrap('m3-v1', repeat('e', 64));

-- This later write changes the current aggregate but must not change the
-- aggregate count or the completed history set bound by the bootstrap token.
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000204',
    timestamptz '2026-05-04 00:00:00+00',
    '00000000-0000-4000-8000-000000001204'
);

INSERT INTO pg_temp.history_count_snapshot (label, response)
SELECT 'first-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.history_count_snapshot
      WHERE label = 'bootstrap'),
    NULL,
    'mountain-001',
    2
);
INSERT INTO pg_temp.history_count_snapshot (label, response)
SELECT 'second-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.history_count_snapshot
      WHERE label = 'bootstrap'),
    (SELECT response ->> 'nextCursor'
       FROM pg_temp.history_count_snapshot
      WHERE label = 'first-page'),
    'mountain-001',
    2
);

SELECT is(
    (SELECT (aggregate_item ->> 'visitCount')::integer
       FROM pg_temp.history_count_snapshot AS snapshot
       CROSS JOIN LATERAL jsonb_array_elements(snapshot.response -> 'aggregates') AS aggregate_item
      WHERE snapshot.label = 'bootstrap'
        AND aggregate_item ->> 'mountainID' = 'mountain-001'),
    3,
    'the bootstrap aggregate records three visits at its snapshot version'
);
SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '3'
            AND jsonb_array_length(response -> 'items') = 2
            AND response ->> 'complete' = 'false'
            AND NOT response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000204')
            )
       FROM pg_temp.history_count_snapshot
      WHERE label = 'first-page'),
    'the first page remains bound to the pre-write snapshot count'
);
SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '3'
            AND jsonb_array_length(response -> 'items') = 1
            AND response ->> 'complete' = 'true'
            AND response ->> 'nextCursor' IS NULL
       FROM pg_temp.history_count_snapshot
      WHERE label = 'second-page'),
    'the final page completes the same snapshot'
);
SELECT is(
    (SELECT count(*)
       FROM pg_temp.history_count_snapshot AS page
       CROSS JOIN LATERAL jsonb_array_elements(page.response -> 'items') AS item
      WHERE page.label IN ('first-page', 'second-page')),
    (SELECT (aggregate_item ->> 'visitCount')::bigint
       FROM pg_temp.history_count_snapshot AS snapshot
       CROSS JOIN LATERAL jsonb_array_elements(snapshot.response -> 'aggregates') AS aggregate_item
      WHERE snapshot.label = 'bootstrap'
        AND aggregate_item ->> 'mountainID' = 'mountain-001'),
    'the completed history page count equals the aggregate count at the bound snapshot'
);

SELECT * FROM finish();
ROLLBACK;
