-- M5-READ-001: only accepted canonical pairs can read a friend passport, and
-- that passport is an aggregate-only, short-lived server-authorized projection.
BEGIN;

SELECT plan(10);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m5', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);

CREATE OR REPLACE FUNCTION pg_temp.set_m5_claims(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor_id::text,
            'iss', 'https://issuer.invalid/m5',
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

CREATE TEMP TABLE pg_temp.m5_friend_read (
    name text PRIMARY KEY,
    value jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON pg_temp.m5_friend_read TO authenticated;

INSERT INTO public.profiles (actor_id)
VALUES ('11111111-1111-4111-8111-111111111111');
INSERT INTO public.passport_aggregates (
    actor_id,
    mountain_id,
    visit_count,
    plan_state,
    stamp_source_visit_id,
    stamp_earned_at,
    stamp_verification_method,
    aggregate_version,
    global_version
) VALUES (
    '11111111-1111-4111-8111-111111111111',
    (SELECT mountain_id FROM public.m3_known_mountains ORDER BY ordinal LIMIT 1),
    2,
    'active_manual',
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    clock_timestamp(),
    'manual',
    7,
    11
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'aCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'aRandomRead', public.m5_read_friend_passport('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_friend_read WHERE name = 'aCode')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'aRandomRead'),
    'unavailable',
    'a random or pre-acceptance friend reference cannot read a passport'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'aAccept', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_friend_read WHERE name = 'bRequest'))::uuid,
    'accept'
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bFriends', public.m5_list_friends();
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bRead', public.m5_read_friend_passport(
    ((SELECT value -> 'friends' -> 0 ->> 'friendRef'
        FROM pg_temp.m5_friend_read WHERE name = 'bFriends'))::uuid
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'bRead'),
    'ok',
    'an accepted friend reference can read the aggregate passport projection'
);
SELECT ok(
    (SELECT jsonb_array_length(value -> 'mountains') FROM pg_temp.m5_friend_read WHERE name = 'bRead') = 1
    AND (SELECT value -> 'mountains' -> 0 ->> 'mountainId' FROM pg_temp.m5_friend_read WHERE name = 'bRead')
        = (SELECT mountain_id FROM public.m3_known_mountains ORDER BY ordinal LIMIT 1)
    AND (SELECT (value -> 'mountains' -> 0 ->> 'visitCount')::integer FROM pg_temp.m5_friend_read WHERE name = 'bRead') = 2,
    'the friend response contains only the current known-mountain aggregate projection'
);
SELECT ok(
    NOT ((SELECT value FROM pg_temp.m5_friend_read WHERE name = 'bRead') ?| ARRAY[
        'actorId', 'history', 'visits', 'visitId', 'visitedAt', 'recordedAt', 'planTimes'
    ])
    AND NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(
              (SELECT value -> 'mountains' FROM pg_temp.m5_friend_read WHERE name = 'bRead')
          ) AS mountain_row
         WHERE mountain_row ?| ARRAY[
             'visitId', 'visitedAt', 'recordedAt', 'history', 'planFirstVisitId', 'stampEarnedAt'
         ]
    ),
    'the friend projection contains no visit identifiers, times, history, or plan times'
);
SELECT ok(
    (SELECT (value ->> 'leaseExpiresAt')::timestamptz FROM pg_temp.m5_friend_read WHERE name = 'bRead')
        > clock_timestamp()
    AND (SELECT (value ->> 'leaseExpiresAt')::timestamptz FROM pg_temp.m5_friend_read WHERE name = 'bRead')
        <= clock_timestamp() + interval '30 seconds',
    'the server-issued friend authorization lease expires no later than thirty seconds'
);

SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'cReadBReference', public.m5_read_friend_passport(
    ((SELECT value -> 'friends' -> 0 ->> 'friendRef'
        FROM pg_temp.m5_friend_read WHERE name = 'bFriends'))::uuid
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'cReadBReference'),
    'unavailable',
    'a recipient-scoped friend reference cannot be replayed by another actor'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'aBlock', public.m5_block_friend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_friend_read WHERE name = 'aAccept'))::uuid
);
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'aReadAfterBlock', public.m5_read_friend_passport(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_friend_read WHERE name = 'aAccept'))::uuid
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bReadAfterBlock', public.m5_read_friend_passport(
    ((SELECT value -> 'friends' -> 0 ->> 'friendRef'
        FROM pg_temp.m5_friend_read WHERE name = 'bFriends'))::uuid
);
INSERT INTO pg_temp.m5_friend_read (name, value)
SELECT 'bLookupAfterBlock', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_friend_read WHERE name = 'aCode')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'aReadAfterBlock'),
    'unavailable',
    'a block immediately removes the blocker''s own friend-read authority'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'bReadAfterBlock'),
    'unavailable',
    'a block immediately removes the blocked actor''s friend-read authority'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_friend_read WHERE name = 'bLookupAfterBlock'),
    'unavailable',
    'a block denies named-code lookup in the blocked direction as well'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'public'
           AND column_row.table_name IN ('friendships', 'friend_revocation_events')
           AND column_row.column_name IN ('visit_id', 'visited_at', 'recorded_at', 'history_token', 'plan_time')
    ),
    'M5 social authority persists no friend visit, history, or plan-time detail'
);

SELECT * FROM finish();
ROLLBACK;
