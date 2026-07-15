-- Local deterministic fixture only. It verifies that compacted opaque history
-- artifacts fail closed and never publish a partial history response.
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
            'iss', 'https://issuer.invalid/m3-history-compaction',
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

CREATE TEMP TABLE pg_temp.history_compaction (
    label text PRIMARY KEY,
    response jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.history_compaction TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-history-compaction', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-history-compaction-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('f', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;

SET LOCAL ROLE authenticated;

SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000301',
    timestamptz '2026-06-01 00:00:00+00',
    '00000000-0000-4000-8000-000000001301'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000302',
    timestamptz '2026-06-02 00:00:00+00',
    '00000000-0000-4000-8000-000000001302'
);

INSERT INTO pg_temp.history_compaction (label, response)
SELECT 'bootstrap-token', public.m3_self_bootstrap('m3-v1', repeat('f', 64));
INSERT INTO pg_temp.history_compaction (label, response)
SELECT 'token-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.history_compaction
      WHERE label = 'bootstrap-token'),
    NULL,
    'mountain-001',
    1
);
INSERT INTO pg_temp.history_compaction (label, response)
SELECT 'bootstrap-cursor', public.m3_self_bootstrap('m3-v1', repeat('f', 64));
INSERT INTO pg_temp.history_compaction (label, response)
SELECT 'cursor-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.history_compaction
      WHERE label = 'bootstrap-cursor'),
    NULL,
    'mountain-001',
    1
);

SELECT ok(
    (SELECT token_page.response ->> 'nextCursor' IS NOT NULL
            AND cursor_page.response ->> 'nextCursor' IS NOT NULL
       FROM pg_temp.history_compaction AS token_page
       JOIN pg_temp.history_compaction AS cursor_page
         ON cursor_page.label = 'cursor-page'
      WHERE token_page.label = 'token-page'),
    'fixtures issue opaque continuation cursors before compaction'
);

RESET ROLE;

UPDATE public.m3_history_tokens
   SET compacted_at = created_at
 WHERE token_id = (
    SELECT split_part(response ->> 'historyToken', '.', 3)::uuid
      FROM pg_temp.history_compaction
     WHERE label = 'bootstrap-token'
 );
UPDATE public.m3_history_cursors
   SET compacted_at = created_at
 WHERE cursor_id = (
    SELECT split_part(response ->> 'nextCursor', '.', 3)::uuid
      FROM pg_temp.history_compaction
     WHERE label = 'cursor-page'
 );

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            response ->> 'historyToken',
            NULL,
            'mountain-001',
            1
        )
          FROM pg_temp.history_compaction
         WHERE label = 'bootstrap-token'
    $$,
    'PT409',
    'passport sync history request rejected',
    'a compacted history token fails before any first-page response can publish'
);
SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            response ->> 'historyToken',
            NULL,
            'mountain-001',
            1
        )
          FROM pg_temp.history_compaction
         WHERE label = 'bootstrap-token'
    $$,
    'PT409',
    'passport sync history request rejected',
    'a compacted history token deterministically fails closed on retry'
);
SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            bootstrap.response ->> 'historyToken',
            page.response ->> 'nextCursor',
            'mountain-001',
            1
        )
          FROM pg_temp.history_compaction AS bootstrap
          JOIN pg_temp.history_compaction AS page
            ON page.label = 'cursor-page'
         WHERE bootstrap.label = 'bootstrap-cursor'
    $$,
    'PT409',
    'passport sync history request rejected',
    'a compacted cursor fails before its continuation can publish a partial page'
);

SELECT * FROM finish();
ROLLBACK;
