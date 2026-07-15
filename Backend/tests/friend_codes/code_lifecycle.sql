-- M5-CODE-001: friend codes are normalized high-entropy capabilities and the
-- canonical-pair lifecycle is request, cancel/decline, accept, unfriend, block.
BEGIN;

SELECT plan(17);

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

CREATE TEMP TABLE pg_temp.m5_lifecycle (
    name text PRIMARY KEY,
    value jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON pg_temp.m5_lifecycle TO authenticated;

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'aCodeInitial', public.m5_get_friend_code();
RESET ROLE;

SELECT ok(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial') = 'ok'
    AND (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial') ~ '^[0-9A-F]{40}$'
    AND (SELECT (value ->> 'codeGeneration')::bigint FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial') = 1,
    'a new code is a 160-bit uppercase normalized capability at generation one'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.friend_codes AS code_row
         WHERE code_row.actor_id = '11111111-1111-4111-8111-111111111111'
           AND code_row.code_hash = encode(
               extensions.digest(
                   (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial'),
                   'sha256'
               ),
               'hex'
           )
    ),
    'the stored code is addressed by its SHA-256 hash index'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'aCodeReplacement', public.m5_regenerate_friend_code();
RESET ROLE;

SELECT ok(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
        <> (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial')
    AND (SELECT (value ->> 'codeGeneration')::bigint FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement') = 2,
    'regeneration invalidates the old code and advances its generation'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'oldCodeLookup', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeInitial')
);
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'normalizedLookup', public.m5_lookup_friend_code(
    lower(
        substr(
            (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement'),
            1,
            20
        ) || '-' || substr(
            (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement'),
            21
        )
    )
);
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'firstRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'oldCodeLookup'),
    'unavailable',
    'a regenerated code cannot be used for discovery'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'normalizedLookup'),
    'available',
    'case and hyphen normalization preserves only a valid named-code lookup'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'firstRequest'),
    'pending',
    'a code-only request creates a pending canonical pair'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'incomingBeforeDecline', public.m5_list_incoming_friend_requests();
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'decline', public.m5_respond_to_friend_request(
    ((SELECT value -> 'requests' -> 0 ->> 'requestRef'
        FROM pg_temp.m5_lifecycle WHERE name = 'incomingBeforeDecline'))::uuid,
    'decline'
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'incomingBeforeDecline'),
    'ok',
    'only the recipient can list its opaque incoming request reference'
);
SELECT is(
    (SELECT value -> 'requests' -> 0 ->> 'requestRef'
        FROM pg_temp.m5_lifecycle WHERE name = 'incomingBeforeDecline'),
    (SELECT value ->> 'requestRef' FROM pg_temp.m5_lifecycle WHERE name = 'firstRequest'),
    'the incoming request carries the sender-created opaque request reference'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'decline'),
    'declined',
    'the recipient can decline a pending request'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'secondRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
);
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'cancel', public.m5_cancel_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_lifecycle WHERE name = 'secondRequest'))::uuid
);
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'thirdRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'cancel'),
    'cancelled',
    'the requester can cancel its own pending request'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'thirdRequest'),
    'pending',
    'a cancelled pair can issue a new request'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'accept', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_lifecycle WHERE name = 'thirdRequest'))::uuid,
    'accept'
);
RESET ROLE;

SELECT ok(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'accept') = 'accepted'
    AND (SELECT value ? 'friendRef' FROM pg_temp.m5_lifecycle WHERE name = 'accept'),
    'acceptance returns only the recipient-scoped opaque friend reference'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'bFriends', public.m5_list_friends();
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'unfriend', public.m5_unfriend(
    ((SELECT value -> 'friends' -> 0 ->> 'friendRef'
        FROM pg_temp.m5_lifecycle WHERE name = 'bFriends'))::uuid
);
RESET ROLE;

SELECT is(
    (SELECT jsonb_array_length(value -> 'friends') FROM pg_temp.m5_lifecycle WHERE name = 'bFriends'),
    1,
    'accepted friendship is represented only by a recipient-scoped friend reference'
);
SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'unfriend'),
    'unfriended',
    'an accepted actor can unfriend using only its own friend reference'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'fourthRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
);
RESET ROLE;
SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'acceptForBlock', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_lifecycle WHERE name = 'fourthRequest'))::uuid,
    'accept'
);
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'block', public.m5_block_friend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_lifecycle WHERE name = 'acceptForBlock'))::uuid
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'block'),
    'blocked',
    'a recipient can permanently block an accepted canonical pair'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_lifecycle (name, value)
SELECT 'blockedRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_lifecycle WHERE name = 'aCodeReplacement')
);
RESET ROLE;

SELECT is(
    (SELECT value ->> 'status' FROM pg_temp.m5_lifecycle WHERE name = 'blockedRequest'),
    'unavailable',
    'a block denies a new request in the blocked direction'
);
SELECT is(
    (SELECT state::text FROM public.friendships
      WHERE pair_low_actor_id = '11111111-1111-4111-8111-111111111111'
        AND pair_high_actor_id = '22222222-2222-4222-8222-222222222222'),
    'blocked',
    'the canonical pair retains only a deny-both-directions blocked state'
);

SELECT * FROM finish();
ROLLBACK;
