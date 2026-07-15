-- Local deterministic fixture only. It verifies that same-actor writes from
-- another device before and between page requests cannot move a history snapshot.
BEGIN;
-- Test-local grants for internal primitive coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) TO authenticated;

SELECT plan(5);

CREATE OR REPLACE FUNCTION pg_temp.set_m3_fixture_claims(p_actor uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor::text,
            'iss', 'https://issuer.invalid/m3-concurrent-pages',
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

CREATE TEMP TABLE pg_temp.concurrent_history_pages (
    label text PRIMARY KEY,
    response jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.concurrent_history_pages TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-concurrent-pages', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-concurrent-pages-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('d', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;

SET LOCAL ROLE authenticated;

SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000101',
    timestamptz '2026-04-01 00:00:00+00',
    '00000000-0000-4000-8000-000000001101'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000102',
    timestamptz '2026-04-02 00:00:00+00',
    '00000000-0000-4000-8000-000000001102'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000103',
    timestamptz '2026-04-03 00:00:00+00',
    '00000000-0000-4000-8000-000000001103'
);

INSERT INTO pg_temp.concurrent_history_pages (label, response)
SELECT 'bootstrap', public.m3_self_bootstrap('m3-v1', repeat('d', 64));

-- A second device for this actor deletes a snapshot-visible visit and creates a
-- later visit before the first page is consumed.
SELECT public.passport_delete_manual_visit(
    '00000000-0000-4000-8000-000000000103',
    '00000000-0000-4000-8000-000000001104'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000104',
    timestamptz '2026-04-04 00:00:00+00',
    '00000000-0000-4000-8000-000000001105'
);

INSERT INTO pg_temp.concurrent_history_pages (label, response)
SELECT 'first-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'bootstrap'),
    NULL,
    'mountain-001',
    1
);

-- Another same-actor device writes between continuations. These changes also
-- must remain outside the bootstrap snapshot while its deleted rows remain in it.
SELECT public.passport_delete_manual_visit(
    '00000000-0000-4000-8000-000000000102',
    '00000000-0000-4000-8000-000000001106'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000105',
    timestamptz '2026-04-05 00:00:00+00',
    '00000000-0000-4000-8000-000000001107'
);

INSERT INTO pg_temp.concurrent_history_pages (label, response)
SELECT 'second-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'bootstrap'),
    (SELECT response ->> 'nextCursor'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'first-page'),
    'mountain-001',
    1
);
INSERT INTO pg_temp.concurrent_history_pages (label, response)
SELECT 'third-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'bootstrap'),
    (SELECT response ->> 'nextCursor'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'second-page'),
    'mountain-001',
    1
);

SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '3'
            AND response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000103')
            )
            AND NOT response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000104')
            )
            AND response ->> 'complete' = 'false'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'first-page'),
    'writes before the first page do not replace its bound snapshot'
);
SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '3'
            AND response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000102')
            )
            AND NOT response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000104')
            )
            AND NOT response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000105')
            )
            AND response ->> 'complete' = 'false'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'second-page'),
    'writes between pages do not change continuation visibility'
);
SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '3'
            AND response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000101')
            )
            AND response ->> 'nextCursor' IS NULL
            AND response ->> 'complete' = 'true'
       FROM pg_temp.concurrent_history_pages
      WHERE label = 'third-page'),
    'the final continuation completes the original snapshot'
);
SELECT is(
    (SELECT count(*)
       FROM (
           SELECT item ->> 'visitID' AS visit_id
             FROM pg_temp.concurrent_history_pages AS page
             CROSS JOIN LATERAL jsonb_array_elements(page.response -> 'items') AS item
            WHERE page.label IN ('first-page', 'second-page', 'third-page')
       ) AS all_items),
    3::bigint,
    'the completed snapshot publishes exactly its three original rows'
);
SELECT is(
    (SELECT count(DISTINCT item ->> 'visitID')
       FROM pg_temp.concurrent_history_pages AS page
       CROSS JOIN LATERAL jsonb_array_elements(page.response -> 'items') AS item
      WHERE page.label IN ('first-page', 'second-page', 'third-page')),
    3::bigint,
    'history continuations have no overlap despite intervening writes'
);

SELECT * FROM finish();
ROLLBACK;
