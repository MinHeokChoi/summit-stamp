-- M5-STREAM-001: revocations are opaque, recipient-only, ordered by a durable
-- generation/sequence cursor, and never leak their actor, reason, or timestamp.
BEGIN;

SELECT plan(15);

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

CREATE TEMP TABLE pg_temp.m5_stream (
    name text PRIMARY KEY,
    value jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON pg_temp.m5_stream TO authenticated;

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'aCode', public.m5_get_friend_code();
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bInitialGap', public.m5_read_revocations(0, 0);
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bInitialCursor', public.m5_read_revocations(1, 0);
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bRequestA', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_stream WHERE name = 'aCode')
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'cCode', public.m5_get_friend_code();
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_stream WHERE name = 'bInitialGap'),
    'gap',
    'a missing or stale stream generation produces a fail-closed cursor gap'
);
SELECT ok(
    (SELECT (value ->> 'generation')::bigint FROM pg_temp.m5_stream WHERE name = 'bInitialGap') = 1
    AND (SELECT (value ->> 'sequence')::bigint FROM pg_temp.m5_stream WHERE name = 'bInitialGap') = 0,
    'the initial gap reports the current generation and last sequence for reset'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_stream WHERE name = 'bInitialCursor'),
    'ok',
    'a matching generation and sequence establishes the recipient stream cursor'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'aAcceptB', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_stream WHERE name = 'bRequestA'))::uuid,
    'accept'
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bFriendsAfterA', public.m5_list_friends();
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bRequestC', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_stream WHERE name = 'cCode')
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'cAcceptB', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_stream WHERE name = 'bRequestC'))::uuid,
    'accept'
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bFriendsAfterC', public.m5_list_friends();
RESET ROLE;

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'aUnfriendB', public.m5_unfriend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'aAcceptB'))::uuid
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'cBlockB', public.m5_block_friend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'cAcceptB'))::uuid
);
RESET ROLE;
-- Extend B's fixture beyond the fixed revocation page size without exposing
-- these opaque recipient references through the RPC.
INSERT INTO public.friend_revocation_events (
    recipient_actor_id,
    generation,
    sequence,
    friend_ref
)
SELECT
    '22222222-2222-4222-8222-222222222222'::uuid,
    1,
    fixture_event.sequence,
    format(
        '00000000-0000-4000-8000-%s',
        lpad(fixture_event.sequence::text, 12, '0')
    )::uuid
  FROM generate_series(3, 258) AS fixture_event(sequence);

UPDATE public.friend_revocation_streams
   SET last_sequence = 258,
       updated_at = clock_timestamp()
 WHERE recipient_actor_id = '22222222-2222-4222-8222-222222222222'::uuid;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bEvents', public.m5_read_revocations(1, 0);
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bNextPage', public.m5_read_revocations(
    1,
    (SELECT (value ->> 'sequence')::bigint
       FROM pg_temp.m5_stream
      WHERE name = 'bEvents')
);
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bAtHead', public.m5_read_revocations(
    1,
    (SELECT (value ->> 'sequence')::bigint
       FROM pg_temp.m5_stream
      WHERE name = 'bNextPage')
);
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'bFutureCursor', public.m5_read_revocations(
    1,
    (SELECT (value ->> 'sequence')::bigint + 1
       FROM pg_temp.m5_stream
      WHERE name = 'bNextPage')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_stream WHERE name = 'bEvents'),
    'ok',
    'the revocation recipient can fetch its ordered stream events'
);
SELECT ok(
    (SELECT jsonb_array_length(value -> 'events')
       FROM pg_temp.m5_stream
      WHERE name = 'bEvents') <= 256
    AND (SELECT jsonb_array_length(value -> 'events')
           FROM pg_temp.m5_stream
          WHERE name = 'bEvents') = 256,
    'the first recipient revocation page is bounded at 256 events'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(
              (SELECT value -> 'events'
                 FROM pg_temp.m5_stream
                WHERE name = 'bEvents')
          ) WITH ORDINALITY AS event_row(event_value, ordinal)
         WHERE (event_value ->> 'sequence')::bigint <> ordinal
    )
    AND (SELECT (value ->> 'sequence')::bigint
           FROM pg_temp.m5_stream
          WHERE name = 'bEvents')
        = (SELECT (value -> 'events' -> 255 ->> 'sequence')::bigint
             FROM pg_temp.m5_stream
            WHERE name = 'bEvents'),
    'the first page is contiguous and its cursor equals its final event'
);
SELECT ok(
    NOT (
        (SELECT value
           FROM pg_temp.m5_stream
          WHERE name = 'bEvents')
        ?| ARRAY['total', 'totalCount', 'backlog', 'backlogCount']
    )
    AND NOT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(
              (SELECT value -> 'events' FROM pg_temp.m5_stream WHERE name = 'bEvents')
          ) AS event_row
         WHERE event_row ?| ARRAY[
             'actorId',
             'revokedBy',
             'reason',
             'createdAt',
             'timestamp',
             'friendCode'
         ]
    ),
    'revocation pages expose no backlog, actor, reason, or time fields'
);
SELECT ok(
    (SELECT value -> 'events' -> 0 ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'bEvents')
        = (SELECT value -> 'friends' -> 0 ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'bFriendsAfterA')
    AND (SELECT value -> 'events' -> 1 ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'bEvents')
        = (SELECT value -> 'friends' -> 1 ->> 'friendRef' FROM pg_temp.m5_stream WHERE name = 'bFriendsAfterC'),
    'each event names only B''s recipient-scoped reference that must be zeroized'
);
SELECT ok(
    (SELECT jsonb_array_length(value -> 'events')
       FROM pg_temp.m5_stream
      WHERE name = 'bNextPage') = 2
    AND (SELECT (value -> 'events' -> 0 ->> 'sequence')::bigint
           FROM pg_temp.m5_stream
          WHERE name = 'bNextPage')
        = (SELECT (value ->> 'sequence')::bigint + 1
             FROM pg_temp.m5_stream
            WHERE name = 'bEvents')
    AND (SELECT (value -> 'events' -> 1 ->> 'sequence')::bigint
           FROM pg_temp.m5_stream
          WHERE name = 'bNextPage')
        = (SELECT (value ->> 'sequence')::bigint + 2
             FROM pg_temp.m5_stream
            WHERE name = 'bEvents')
    AND (SELECT (value ->> 'sequence')::bigint
           FROM pg_temp.m5_stream
          WHERE name = 'bNextPage')
        = (SELECT (value -> 'events' -> 1 ->> 'sequence')::bigint
             FROM pg_temp.m5_stream
            WHERE name = 'bNextPage'),
    'the next page resumes contiguously from the returned cursor'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_stream WHERE name = 'bAtHead'),
    'ok',
    'a cursor at the current sequence receives no duplicate event'
);
SELECT ok(
    (SELECT value -> 'events' FROM pg_temp.m5_stream WHERE name = 'bAtHead') = '[]'::jsonb
    AND (SELECT (value ->> 'sequence')::bigint FROM pg_temp.m5_stream WHERE name = 'bAtHead')
        = (SELECT (value ->> 'sequence')::bigint FROM pg_temp.m5_stream WHERE name = 'bNextPage'),
    'a cursor at the current sequence receives no duplicate event and remains unchanged'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_stream WHERE name = 'bFutureCursor'),
    'gap',
    'a sequence gap is fail-closed rather than silently accepting a lost event'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'aEvents', public.m5_read_revocations(1, 0);
RESET ROLE;
SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_stream (name, value)
SELECT 'cEvents', public.m5_read_revocations(1, 0);
RESET ROLE;

SELECT is(
    (SELECT value -> 'events' FROM pg_temp.m5_stream WHERE name = 'aEvents'),
    '[]'::jsonb,
    'the unfriending actor cannot read the recipient''s revocation event'
);
SELECT is(
    (SELECT value -> 'events' FROM pg_temp.m5_stream WHERE name = 'cEvents'),
    '[]'::jsonb,
    'the blocking actor cannot read the recipient''s revocation event'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT * FROM public.friend_revocation_events$$,
    '42501', NULL,
    'authenticated callers cannot enumerate revocation events outside the recipient RPC'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
