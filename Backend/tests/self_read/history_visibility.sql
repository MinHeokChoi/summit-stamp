-- Local deterministic fixture only. It validates M3 database read semantics and
-- does not exercise Apple, a release build, or protected staging evidence.
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
            'iss', 'https://issuer.invalid/m3-self-read',
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

CREATE TEMP TABLE pg_temp.bootstrap_tokens (
    history_token text NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.bootstrap_tokens TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-self-read', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);

INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-self-read-history-visibility-fixture', 'sha256'), true);

DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('a', 64),
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
) VALUES
    (
        '00000000-0000-4000-8000-000000000001',
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        timestamptz '2026-01-01 00:00:00+00',
        timestamptz '2026-01-01 00:00:00+00',
        'manual',
        1,
        1
    ),
    (
        '00000000-0000-4000-8000-000000000002',
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        timestamptz '2026-01-02 00:00:00+00',
        timestamptz '2026-01-02 00:00:00+00',
        'gps_verified',
        2,
        2
    );
INSERT INTO public.passport_global_state (actor_id, global_version, updated_at)
VALUES (
    '11111111-1111-4111-8111-111111111111',
    2,
    timestamptz '2026-01-02 00:00:00+00'
);

SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.bootstrap_tokens (history_token)
SELECT public.m3_self_bootstrap('m3-v1', repeat('a', 64)) ->> 'historyToken';

SELECT ok(
    (
        SELECT jsonb_array_length(
                   public.m3_self_bootstrap('m3-v1', repeat('a', 64)) -> 'mountains'
               ) = 100
    ),
    'bootstrap returns exactly the configured 100 opaque MountainIDs'
);

RESET ROLE;

-- Publish a later delete and later create after the snapshot token exists. The
-- history query below must still expose only rows visible at snapshot version 2.
UPDATE public.passport_visits
   SET deleted_aggregate_version = 3,
       deleted_global_version = 3,
       deleted_at = timestamptz '2026-01-03 00:00:00+00'
 WHERE visit_id = '00000000-0000-4000-8000-000000000002';
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
    '00000000-0000-4000-8000-000000000003',
    '11111111-1111-4111-8111-111111111111',
    'mountain-001',
    timestamptz '2026-01-03 00:00:00+00',
    timestamptz '2026-01-03 00:00:00+00',
    'manual',
    3,
    3
);
UPDATE public.passport_global_state
   SET global_version = 3,
       updated_at = timestamptz '2026-01-03 00:00:00+00'
 WHERE actor_id = '11111111-1111-4111-8111-111111111111';

SET LOCAL ROLE authenticated;

SELECT ok(
    (
        SELECT page.response ->> 'snapshotVersion' = '2'
           AND jsonb_array_length(page.response -> 'items') = 2
           AND page.response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000001')
           )
           AND page.response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000002')
           )
           AND NOT page.response -> 'items' @> jsonb_build_array(
                jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000003')
           )
          FROM pg_temp.bootstrap_tokens AS token
          CROSS JOIN LATERAL public.m3_self_history_page(
              token.history_token,
              NULL,
              'mountain-001',
              100
          ) AS page(response)
    ),
    'history uses created <= snapshot and deleted > snapshot visibility'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            NULL,
            'mountain-101',
            100
        )
          FROM pg_temp.bootstrap_tokens
    $$,
    '22023',
    'passport mountain identifier rejected',
    'history rejects an unknown MountainID before returning any rows'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            NULL,
            'mountain-001',
            101
        )
          FROM pg_temp.bootstrap_tokens
    $$,
    '22023',
    'passport sync page size rejected',
    'history rejects an unbound page size before returning any rows'
);

SELECT * FROM finish();
ROLLBACK;
