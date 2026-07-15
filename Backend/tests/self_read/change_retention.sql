-- Local deterministic fixture only. It validates the M3 90-day resync boundary
-- and audit preservation; it does not exercise protected staging evidence.
BEGIN;

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
            'iss', 'https://issuer.invalid/m3-retention',
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

CREATE TEMP TABLE pg_temp.retention_tokens (
    history_token text NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.retention_tokens TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-retention', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-self-read-retention-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('c', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;
INSERT INTO public.profiles (actor_id)
VALUES ('11111111-1111-4111-8111-111111111111');
INSERT INTO public.passport_aggregates (actor_id, mountain_id)
VALUES ('11111111-1111-4111-8111-111111111111', 'mountain-001');
INSERT INTO public.passport_visits (
    visit_id,
    actor_id,
    mountain_id,
    visited_at,
    recorded_at,
    verification_method,
    created_aggregate_version,
    created_global_version
) VALUES (
    '00000000-0000-4000-8000-000000000021',
    '11111111-1111-4111-8111-111111111111',
    'mountain-001',
    timestamptz '2026-03-01 00:00:00+00',
    timestamptz '2026-03-01 00:00:00+00',
    'manual',
    1,
    1
);

SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.retention_tokens (history_token)
SELECT public.m3_self_bootstrap('m3-v1', repeat('c', 64)) ->> 'historyToken';

RESET ROLE;

UPDATE public.passport_global_state
   SET global_version = 2,
       updated_at = clock_timestamp()
 WHERE actor_id = '11111111-1111-4111-8111-111111111111';
INSERT INTO public.passport_changes (
    actor_id,
    mountain_id,
    operation,
    aggregate_version,
    global_version,
    payload,
    result,
    created_at,
    expires_at
) VALUES
    (
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        'manual_visit_create',
        1,
        1,
        jsonb_build_object('mountain_id', 'mountain-001'),
        jsonb_build_object('global_version', 1),
        clock_timestamp() - interval '91 days',
        clock_timestamp() - interval '1 day'
    ),
    (
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        'plan_add',
        2,
        2,
        jsonb_build_object('mountain_id', 'mountain-001'),
        jsonb_build_object('global_version', 2),
        clock_timestamp(),
        clock_timestamp() + interval '91 days'
    );

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        SELECT public.m3_self_changes(history_token, NULL, 500)
          FROM pg_temp.retention_tokens
    $$,
    'PT410',
    'passport sync history expired',
    'an expired change in the bootstrap-to-target window returns the required gone contract'
);

SELECT ok(
    NOT has_table_privilege('authenticated', 'public.passport_visits', 'DELETE')
    AND NOT has_table_privilege('authenticated', 'public.passport_changes', 'DELETE'),
    'authenticated clients cannot erase immutable visit audit or retention facts directly'
);

RESET ROLE;

UPDATE public.m3_history_tokens
   SET created_at = clock_timestamp() - interval '91 days',
       expires_at = clock_timestamp() - interval '1 day'
 WHERE token_id = (
    SELECT split_part(history_token, '.', 3)::uuid
      FROM pg_temp.retention_tokens
 );

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            NULL,
            'mountain-001',
            100
        )
          FROM pg_temp.retention_tokens
    $$,
    'PT409',
    'passport sync history request rejected',
    'an expired 90-day history token fails closed before returning audit rows'
);

RESET ROLE;

SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.passport_visits
         WHERE visit_id = '00000000-0000-4000-8000-000000000021'
           AND deleted_global_version IS NULL
    ),
    'resync retention leaves immutable visit audit history intact'
);

SELECT * FROM finish();
ROLLBACK;
