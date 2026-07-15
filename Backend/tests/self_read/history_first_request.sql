-- Local deterministic fixture only. It verifies that history starts from an
-- opaque bootstrap token, never from an implicit latest read or mixed cursor.
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
            'iss', 'https://issuer.invalid/m3-history-first-request',
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

CREATE TEMP TABLE pg_temp.history_first_request (
    label text PRIMARY KEY,
    response jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.history_first_request TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-history-first-request', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-history-first-request-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('c', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;

SET LOCAL ROLE authenticated;

SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000011',
    timestamptz '2026-03-01 00:00:00+00',
    '00000000-0000-4000-8000-000000001011'
);
SELECT public.passport_create_manual_visit(
    'mountain-001',
    '00000000-0000-4000-8000-000000000012',
    timestamptz '2026-03-02 00:00:00+00',
    '00000000-0000-4000-8000-000000001012'
);

INSERT INTO pg_temp.history_first_request (label, response)
SELECT 'bootstrap-one', public.m3_self_bootstrap('m3-v1', repeat('c', 64));
INSERT INTO pg_temp.history_first_request (label, response)
SELECT 'bootstrap-two', public.m3_self_bootstrap('m3-v1', repeat('c', 64));
INSERT INTO pg_temp.history_first_request (label, response)
SELECT 'first-page', public.m3_self_history_page(
    (SELECT response ->> 'historyToken'
       FROM pg_temp.history_first_request
      WHERE label = 'bootstrap-one'),
    NULL,
    'mountain-001',
    1
);

SELECT ok(
    (SELECT response ->> 'snapshotVersion' = '2'
            AND jsonb_array_length(response -> 'items') = 1
            AND response ->> 'nextCursor' IS NOT NULL
       FROM pg_temp.history_first_request
      WHERE label = 'first-page'),
    'the first history page succeeds only from its bootstrap-issued token'
);

SELECT throws_ok(
    $$SELECT public.m3_self_history_page(NULL, NULL, 'mountain-001', 1)$$,
    'PT409',
    'passport sync token rejected',
    'history rejects a first request without a bootstrap token'
);
SELECT throws_ok(
    $$SELECT public.m3_self_history_page('latest', NULL, 'mountain-001', 1)$$,
    'PT409',
    'passport sync token rejected',
    'history denies an implicit latest request instead of selecting a fresh snapshot'
);
SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            second_bootstrap.response ->> 'historyToken',
            first_page.response ->> 'nextCursor',
            'mountain-001',
            1
        )
          FROM pg_temp.history_first_request AS first_page
          JOIN pg_temp.history_first_request AS second_bootstrap
            ON second_bootstrap.label = 'bootstrap-two'
         WHERE first_page.label = 'first-page'
    $$,
    'PT409',
    'passport sync history request rejected',
    'a cursor cannot be mixed with a later bootstrap token'
);

SELECT * FROM finish();
ROLLBACK;
