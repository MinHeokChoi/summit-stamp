-- Local deterministic fixture only. It validates actor-bound M3 change continuations
-- and does not exercise Apple, a release build, or protected staging evidence.
BEGIN;
-- Test-local grant for internal primitive coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;

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
            'iss', 'https://issuer.invalid/m3-changes',
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

CREATE TEMP TABLE pg_temp.change_sync_sessions (
    history_token text NOT NULL,
    alternate_history_token text NOT NULL
) ON COMMIT DROP;
CREATE TEMP TABLE pg_temp.change_page_one (
    response jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON pg_temp.change_sync_sessions TO authenticated;
GRANT SELECT, INSERT ON pg_temp.change_page_one TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-changes', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-change-continuity-fixture', 'sha256'), true);
DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('mountain-%s', lpad(ordinal::text, 3, '0')),
       repeat('b', 64),
       ordinal::smallint
  FROM generate_series(1, 100) AS ordinal;
INSERT INTO public.profiles (actor_id)
VALUES ('11111111-1111-4111-8111-111111111111');
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
        'plan_add',
        1,
        1,
        jsonb_build_object('mountain_id', 'mountain-001'),
        jsonb_build_object('global_version', 1),
        clock_timestamp(),
        clock_timestamp() + interval '91 days'
    ),
    (
        '11111111-1111-4111-8111-111111111111',
        'mountain-002',
        'plan_add',
        1,
        2,
        jsonb_build_object('mountain_id', 'mountain-002'),
        jsonb_build_object('global_version', 2),
        clock_timestamp(),
        clock_timestamp() + interval '91 days'
    );
INSERT INTO public.passport_global_state (actor_id, global_version, updated_at)
VALUES (
    '11111111-1111-4111-8111-111111111111',
    2,
    clock_timestamp()
);

SET LOCAL ROLE authenticated;

WITH primary_bootstrap AS (
    SELECT public.m3_self_bootstrap('m3-v1', repeat('b', 64)) AS response
), alternate_bootstrap AS (
    SELECT public.m3_self_bootstrap('m3-v1', repeat('b', 64)) AS response
)
INSERT INTO pg_temp.change_sync_sessions (history_token, alternate_history_token)
SELECT primary_bootstrap.response ->> 'historyToken',
       alternate_bootstrap.response ->> 'historyToken'
  FROM primary_bootstrap
 CROSS JOIN alternate_bootstrap;

RESET ROLE;

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
        'mountain-003',
        'plan_remove',
        2,
        3,
        jsonb_build_object('mountain_id', 'mountain-003'),
        jsonb_build_object('global_version', 3),
        clock_timestamp(),
        clock_timestamp() + interval '91 days'
    ),
    (
        '11111111-1111-4111-8111-111111111111',
        'mountain-004',
        'manual_visit_create',
        3,
        4,
        jsonb_build_object('mountain_id', 'mountain-004'),
        jsonb_build_object('global_version', 4),
        clock_timestamp(),
        clock_timestamp() + interval '91 days'
    );
UPDATE public.passport_global_state
   SET global_version = 4,
       updated_at = clock_timestamp()
 WHERE actor_id = '11111111-1111-4111-8111-111111111111';

SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.change_page_one (response)
SELECT public.m3_self_changes(history_token, NULL, 1)
  FROM pg_temp.change_sync_sessions;

SELECT ok(
    (
        SELECT response ->> 'fromVersion' = '2'
           AND response ->> 'throughVersion' = '4'
           AND response ->> 'nextVersion' = '3'
           AND response ->> 'complete' = 'false'
           AND response ->> 'resyncRequired' = 'false'
           AND response ->> 'nextCursor' ~ '^m3d1\.[1-9][0-9]*\.[0-9a-f-]{36}\.[0-9a-f]{64}$'
           AND response -> 'changes' = jsonb_build_array(
                jsonb_build_object(
                    'globalVersion', 3,
                    'mountainID', 'mountain-003',
                    'operation', 'plan_remove',
                    'aggregateVersion', 2,
                    'result', jsonb_build_object('global_version', 3)
                )
           )
          FROM pg_temp.change_page_one
    ),
    'the bootstrap token baseline cannot be skipped by a caller-supplied version'
);

RESET ROLE;

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
) VALUES (
    '11111111-1111-4111-8111-111111111111',
    'mountain-005',
    'manual_visit_create',
    4,
    5,
    jsonb_build_object('mountain_id', 'mountain-005'),
    jsonb_build_object('global_version', 5),
    clock_timestamp(),
    clock_timestamp() + interval '91 days'
);
UPDATE public.passport_global_state
   SET global_version = 5,
       updated_at = clock_timestamp()
 WHERE actor_id = '11111111-1111-4111-8111-111111111111';

SET LOCAL ROLE authenticated;

SELECT ok(
    (
        SELECT second_page.response ->> 'fromVersion' = '3'
           AND second_page.response ->> 'throughVersion' = '4'
           AND second_page.response ->> 'nextVersion' = '4'
           AND second_page.response ->> 'nextCursor' IS NULL
           AND second_page.response ->> 'complete' = 'true'
           AND second_page.response ->> 'resyncRequired' = 'false'
           AND second_page.response -> 'changes' = jsonb_build_array(
                jsonb_build_object(
                    'globalVersion', 4,
                    'mountainID', 'mountain-004',
                    'operation', 'manual_visit_create',
                    'aggregateVersion', 3,
                    'result', jsonb_build_object('global_version', 4)
                )
           )
          FROM pg_temp.change_sync_sessions AS sync_session
          CROSS JOIN pg_temp.change_page_one AS first_page
          CROSS JOIN LATERAL public.m3_self_changes(
              sync_session.history_token,
              first_page.response ->> 'nextCursor',
              1
          ) AS second_page(response)
    ),
    'writes between pages cannot move a continuation target'
);

SELECT is(
    to_regprocedure('public.m3_self_changes(bigint,integer)'),
    NULL::regprocedure,
    'no public change API accepts a naked client-supplied version'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_changes(
            alternate_history_token,
            response ->> 'nextCursor',
            1
        )
          FROM pg_temp.change_sync_sessions
          CROSS JOIN pg_temp.change_page_one
    $$,
    'PT409',
    'passport sync change request rejected',
    'a change cursor cannot be mixed with another bootstrap history token'
);

SELECT throws_ok(
    $$
        SELECT public.m3_self_changes(
            history_token,
            response ->> 'nextCursor',
            2
        )
          FROM pg_temp.change_sync_sessions
          CROSS JOIN pg_temp.change_page_one
    $$,
    'PT409',
    'passport sync change request rejected',
    'a change cursor cannot be reused with a different page limit'
);

SELECT pg_temp.set_m3_fixture_claims('22222222-2222-4222-8222-222222222222');

SELECT throws_ok(
    $$
        SELECT public.m3_self_changes(
            history_token,
            response ->> 'nextCursor',
            1
        )
          FROM pg_temp.change_sync_sessions
          CROSS JOIN pg_temp.change_page_one
    $$,
    'PT409',
    'passport sync history request rejected',
    'a change continuation cannot cross the actor boundary'
);

SELECT public.passport_add_plan(
    'mountain-010',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
);

RESET ROLE;
SELECT results_eq(
    $$
        SELECT actor_id, global_version
          FROM public.passport_global_state
         WHERE actor_id IN (
             '11111111-1111-4111-8111-111111111111',
             '22222222-2222-4222-8222-222222222222'
         )
         ORDER BY actor_id
    $$,
    $$
        VALUES
            ('11111111-1111-4111-8111-111111111111'::uuid, 5::bigint),
            ('22222222-2222-4222-8222-222222222222'::uuid, 1::bigint)
    $$,
    'interleaved actors advance independent contiguous snapshot sequences'
);
SELECT * FROM finish();
ROLLBACK;
