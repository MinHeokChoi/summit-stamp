-- Local deterministic fixture only. It validates opaque cursor binding and does
-- not exercise Apple, a release build, or protected staging evidence.
BEGIN;

SELECT plan(7);

CREATE OR REPLACE FUNCTION pg_temp.set_m3_fixture_claims(p_actor uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor::text,
            'iss', 'https://issuer.invalid/m3-cursor',
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

CREATE TEMP TABLE pg_temp.history_binding (
    history_token text NOT NULL,
    cursor_token text NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.history_binding TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-cursor', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-self-read-cursor-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('b', 64),
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
        '00000000-0000-4000-8000-000000000011',
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        timestamptz '2026-02-01 00:00:00+00',
        timestamptz '2026-02-01 00:00:00+00',
        'manual',
        1,
        1
    ),
    (
        '00000000-0000-4000-8000-000000000012',
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        timestamptz '2026-02-02 00:00:00+00',
        timestamptz '2026-02-02 00:00:00+00',
        'manual',
        2,
        1
    ),
    (
        '00000000-0000-4000-8000-000000000013',
        '11111111-1111-4111-8111-111111111111',
        'mountain-001',
        timestamptz '2026-02-03 00:00:00+00',
        timestamptz '2026-02-03 00:00:00+00',
        'gps_verified',
        3,
        1
    );
INSERT INTO public.passport_global_state (actor_id, global_version, updated_at)
VALUES (
    '11111111-1111-4111-8111-111111111111',
    1,
    timestamptz '2026-02-03 00:00:00+00'
);

SET LOCAL ROLE authenticated;

WITH bootstrap AS (
    SELECT public.m3_self_bootstrap('m3-v1', repeat('b', 64)) AS response
), first_page AS (
    SELECT bootstrap.response,
           public.m3_self_history_page(
               bootstrap.response ->> 'historyToken',
               NULL,
               'mountain-001',
               1
           ) AS page
      FROM bootstrap
)
INSERT INTO pg_temp.history_binding (history_token, cursor_token)
SELECT response ->> 'historyToken', page ->> 'nextCursor'
  FROM first_page;

SELECT ok(
    (
        SELECT cursor_token ~ '^m3c1\.[1-9][0-9]*\.[0-9a-f-]{36}\.[0-9a-f]{64}$'
          FROM pg_temp.history_binding
    ),
    'first history page returns an opaque signed continuation cursor'
);

SELECT ok(
    (
        SELECT page.response -> 'items' @> jsonb_build_array(
                   jsonb_build_object('visitID', '00000000-0000-4000-8000-000000000012')
               )
          FROM pg_temp.history_binding AS binding
          CROSS JOIN LATERAL public.m3_self_history_page(
              binding.history_token,
              binding.cursor_token,
              'mountain-001',
              1
          ) AS page(response)
    ),
    'cursor continues the same ordered snapshot without replaying the first row'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            cursor_token || '0',
            'mountain-001',
            1
        )
          FROM pg_temp.history_binding
    $$,
    'PT409',
    'passport sync token rejected',
    'tampered cursor fails before exposing a page'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            cursor_token,
            'mountain-001',
            2
        )
          FROM pg_temp.history_binding
    $$,
    'PT409',
    'passport sync history request rejected',
    'cursor cannot be reused with a different page size'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            cursor_token,
            'mountain-002',
            1
        )
          FROM pg_temp.history_binding
    $$,
    'PT409',
    'passport sync history request rejected',
    'cursor cannot be mixed with a different mountain filter'
);

SELECT pg_temp.set_m3_fixture_claims('22222222-2222-4222-8222-222222222222');

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            cursor_token,
            'mountain-001',
            1
        )
          FROM pg_temp.history_binding
    $$,
    'PT409',
    'passport sync history request rejected',
    'a cursor and history token cannot cross the actor boundary'
);

RESET ROLE;
SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');
UPDATE public.m3_history_cursors
   SET compacted_at = created_at
 WHERE cursor_id = (
    SELECT split_part(cursor_token, '.', 3)::uuid
      FROM pg_temp.history_binding
 );

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        SELECT public.m3_self_history_page(
            history_token,
            cursor_token,
            'mountain-001',
            1
        )
          FROM pg_temp.history_binding
    $$,
    'PT409',
    'passport sync history request rejected',
    'compacted cursor input fails closed without returning a partial page'
);

SELECT * FROM finish();
ROLLBACK;
