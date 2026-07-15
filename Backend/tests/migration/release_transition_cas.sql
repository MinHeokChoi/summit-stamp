-- REL-TRANSITION-CAS: later transitions are a strict compare-and-swap chain.
BEGIN;

SELECT plan(11);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m6-cas', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);

CREATE OR REPLACE FUNCTION pg_temp.set_release_claims(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor_id::text,
            'iss', 'https://issuer.invalid/m6-cas',
            'aud', 'authenticated',
            'iat', extract(epoch FROM clock_timestamp())::bigint,
            'role', 'authenticated',
            'app_metadata', jsonb_build_object('provider', 'apple')
        )::text,
        true
    );
    PERFORM set_config('request.jwt.claim.sub', p_actor_id::text, true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    RETURN true;
END;
$function$;

SELECT pg_temp.set_release_claims('11111111-1111-4111-8111-111111111111');

CREATE TEMP TABLE pg_temp.release_cas_values (
    sentinel_sha text NOT NULL,
    first_event_sha text,
    second_event_sha text
) ON COMMIT DROP;
GRANT SELECT ON pg_temp.release_cas_values TO service_role;

INSERT INTO pg_temp.release_cas_values (sentinel_sha)
VALUES (
    m6_private.release_transition_sentinel_sha(
        'release-cas', 'v1.2.3', repeat('a', 40), repeat('c', 64), repeat('b', 64)
    )
);

SET LOCAL ROLE service_role;
SELECT * FROM public.append_release_transition(
    'release-cas', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
    repeat('b', 64), repeat('c', 64), 'disabled', 0,
    (SELECT sentinel_sha FROM pg_temp.release_cas_values),
    repeat('d', 64), repeat('e', 64), '11111111-1111-4111-8111-111111111112'
);
RESET ROLE;

UPDATE pg_temp.release_cas_values
   SET first_event_sha = (
       SELECT event_row.event_sha
         FROM public.release_transition_events AS event_row
        WHERE event_row.release_id = 'release-cas'
          AND event_row.sequence = 1
   );

SET LOCAL ROLE service_role;
SELECT * FROM public.append_release_transition(
    'release-cas', 'compatibility', 'v1.2.3', repeat('a', 40),
    repeat('b', 64), repeat('c', 64), 'disabled', 1,
    (SELECT first_event_sha FROM pg_temp.release_cas_values),
    repeat('f', 64), repeat('0', 64), '11111111-1111-4111-8111-111111111113'
);
RESET ROLE;

UPDATE pg_temp.release_cas_values
   SET second_event_sha = (
       SELECT event_row.event_sha
         FROM public.release_transition_events AS event_row
        WHERE event_row.release_id = 'release-cas'
          AND event_row.sequence = 2
   );

SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.release_transition_events AS event_row
         WHERE event_row.release_id = 'release-cas'
           AND event_row.sequence = 1
           AND event_row.state = 'predeploy-disabled'
    ),
    'the first transition establishes the release chain'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.release_transition_events AS event_row
         WHERE event_row.release_id = 'release-cas'
           AND event_row.sequence = 2
           AND event_row.state = 'compatibility'
           AND event_row.previous_event_sha = (
               SELECT first_event_sha FROM pg_temp.release_cas_values
           )
    ),
    'a later CAS append advances only to compatibility with the exact predecessor'
);
SELECT is(
    (SELECT count(*) FROM public.release_transition_events WHERE release_id = 'release-cas'),
    2::bigint,
    'the valid later append creates exactly one additional event'
);

SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'phase-5', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'enabled', 2,
        (SELECT second_event_sha FROM pg_temp.release_cas_values),
        repeat('1', 64), repeat('2', 64), '11111111-1111-4111-8111-111111111114'
    )$$,
    '22023', NULL,
    'an illegal state skip is rejected without advancing the chain'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 1,
        (SELECT first_event_sha FROM pg_temp.release_cas_values),
        repeat('3', 64), repeat('4', 64), '11111111-1111-4111-8111-111111111115'
    )$$,
    '40001', NULL,
    'a stale replay with an old sequence and event SHA is rejected'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 2, repeat('5', 64),
        repeat('6', 64), repeat('7', 64), '11111111-1111-4111-8111-111111111116'
    )$$,
    '40001', NULL,
    'a wrong predecessor SHA is rejected by compare-and-swap'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 2,
        (SELECT sentinel_sha FROM pg_temp.release_cas_values),
        repeat('8', 64), repeat('9', 64), '11111111-1111-4111-8111-111111111117'
    )$$,
    '22023', NULL,
    'the genesis sentinel is never accepted after sequence one'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('a', 64), 'disabled', 2,
        (SELECT second_event_sha FROM pg_temp.release_cas_values),
        repeat('b', 64), repeat('c', 64), '11111111-1111-4111-8111-111111111118'
    )$$,
    '22023', NULL,
    'a full-context dataset mismatch is rejected after a valid predecessor CAS'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'enabled', 2,
        (SELECT second_event_sha FROM pg_temp.release_cas_values),
        repeat('c', 64), repeat('d', 64), '11111111-1111-4111-8111-111111111119'
    )$$,
    '22023', NULL,
    'a state-incompatible switch value is rejected before any write'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-cas', 'pitr-proof', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 2,
        (SELECT second_event_sha FROM pg_temp.release_cas_values),
        repeat('f', 64), repeat('e', 64), '11111111-1111-4111-8111-111111111120'
    )$$,
    '22023', NULL,
    'an approval SHA already consumed by compatibility cannot authorize pitr proof'
);
RESET ROLE;

SELECT is(
    (SELECT count(*) FROM public.release_transition_events WHERE release_id = 'release-cas'),
    2::bigint,
    'all rejected later calls leave the release chain unchanged'
);

SELECT * FROM finish();
ROLLBACK;
