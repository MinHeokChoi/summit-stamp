-- M5-NONDISCLOSURE-001: friend codes are the only discovery input. Missing,
-- blocked, malformed, self, and rate-limited probes have one opaque response.
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

CREATE TEMP TABLE pg_temp.m5_nondisclosure (
    name text PRIMARY KEY,
    value jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON pg_temp.m5_nondisclosure TO authenticated;

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'aCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'aSelfLookup', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_nondisclosure WHERE name = 'aCode')
);
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'aMalformedLookup', public.m5_lookup_friend_code('not-a-friend-code');
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'bCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'bMissingLookup', public.m5_lookup_friend_code(repeat('0', 40));
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'bRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_nondisclosure WHERE name = 'aCode')
);
RESET ROLE;

SELECT is(
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'aSelfLookup'),
    jsonb_build_object('status', 'unavailable'),
    'self lookup is indistinguishable from every unavailable named-code probe'
);
SELECT is(
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'aMalformedLookup'),
    jsonb_build_object('status', 'unavailable'),
    'malformed code lookup is generic rather than a validation oracle'
);
SELECT is(
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bMissingLookup'),
    jsonb_build_object('status', 'unavailable'),
    'a missing code receives the generic unavailable response'
);
SELECT ok(
    NOT ((SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bMissingLookup') ?| ARRAY[
        'actorId', 'profileId', 'friendCode', 'email', 'phone', 'username'
    ]),
    'a failed discovery response discloses no identity or alternate search field'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'aAccept', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_nondisclosure WHERE name = 'bRequest'))::uuid,
    'accept'
);
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'aBlock', public.m5_block_friend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_nondisclosure WHERE name = 'aAccept'))::uuid
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'bBlockedLookup', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_nondisclosure WHERE name = 'aCode')
);
SELECT public.m5_lookup_friend_code(repeat('1', 40))
  FROM generate_series(1, 30);
INSERT INTO pg_temp.m5_nondisclosure (name, value)
SELECT 'bRateLimitedLookup', public.m5_lookup_friend_code(repeat('2', 40));
RESET ROLE;

SELECT is(
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bBlockedLookup'),
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bMissingLookup'),
    'a block is indistinguishable from a missing code to the blocked actor'
);
SELECT is(
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bRateLimitedLookup'),
    (SELECT value FROM pg_temp.m5_nondisclosure WHERE name = 'bMissingLookup'),
    'a rate-limited lookup has the same generic response as a missing code'
);
SELECT ok(
    (SELECT attempts FROM public.friend_code_rate_limits
      WHERE actor_id = '22222222-2222-4222-8222-222222222222') > 30,
    'the named-code probe budget is enforced server-side without a client bypass'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT * FROM public.friend_codes$$,
    '42501', NULL,
    'authenticated callers cannot enumerate friend codes directly'
);
SELECT throws_ok(
    $$INSERT INTO public.friendships (pair_low_actor_id, pair_high_actor_id, requested_by_actor_id, state) VALUES ('33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444', '33333333-3333-4333-8333-333333333333', 'pending')$$,
    '42501', NULL,
    'authenticated callers cannot manufacture social authorization rows'
);
RESET ROLE;

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname ~ '^m5_(search|find|lookup_.*profile|lookup_.*email|lookup_.*phone|lookup_.*username)'
    ),
    'the public M5 API exposes no alternate profile, contact, or username discovery RPC'
);

SELECT * FROM finish();
ROLLBACK;
