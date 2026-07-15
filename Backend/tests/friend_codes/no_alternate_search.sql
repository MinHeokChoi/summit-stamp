-- SOC-003: M5 discovery is a named friend-code capability only. No public actor,
-- profile, email, phone, contact, or username search path may be introduced.
BEGIN;

SELECT plan(21);

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

CREATE TEMP TABLE pg_temp.m5_soc003 (
    name text PRIMARY KEY,
    value jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON pg_temp.m5_soc003 TO authenticated;

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname ~* '(^|_)(search|find|discover|actor|user|profile|email|phone|contact|username)(_|$)'
    ),
    'the public M5 API has no actor, profile, contact, or general-search RPC'
);

SELECT is(
    (
        SELECT pg_get_function_identity_arguments(procedure_row.oid)
          FROM pg_proc AS procedure_row
         WHERE procedure_row.oid = 'public.m5_lookup_friend_code(text)'::regprocedure
    ),
    'p_friend_code text',
    'the sole discovery RPC accepts one named friend-code input'
);
SELECT is(
    ARRAY(
        SELECT format(
            '%s(%s)',
            procedure_row.proname,
            pg_get_function_identity_arguments(procedure_row.oid)
        )
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname ~* '(^|_)(lookup|search|find|discover)(_|$)'
         ORDER BY procedure_row.proname, pg_get_function_identity_arguments(procedure_row.oid)
    ),
    ARRAY['m5_lookup_friend_code(p_friend_code text)'],
    'the named friend-code lookup is the only public lookup or search RPC'
);

SELECT ok(
    has_function_privilege(
        'authenticated',
        'public.m5_lookup_friend_code(text)'::regprocedure,
        'EXECUTE'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM pg_roles AS role_row
         WHERE role_row.rolname IN ('anon', 'service_role')
           AND has_function_privilege(
               role_row.oid,
               'public.m5_lookup_friend_code(text)'::regprocedure,
               'EXECUTE'
           )
    ),
    'only authenticated callers can invoke the named friend-code lookup RPC'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relkind IN ('v', 'm')
           AND relation_row.relname ~* '(friend|actor|profile|email|phone|contact|username|search|find|discover)'
    ),
    'the public schema has no named social or alternate-discovery view'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_rewrite AS rewrite_row
          JOIN pg_class AS view_row ON view_row.oid = rewrite_row.ev_class
          JOIN pg_namespace AS namespace_row ON namespace_row.oid = view_row.relnamespace
          JOIN pg_depend AS dependency_row ON dependency_row.objid = rewrite_row.oid
         WHERE namespace_row.nspname = 'public'
           AND view_row.relkind IN ('v', 'm')
           AND dependency_row.refobjid IN (
               'public.friend_codes'::regclass,
               'public.friend_code_rate_limits'::regclass,
               'public.friendships'::regclass,
               'public.friend_revocation_streams'::regclass,
               'public.friend_revocation_events'::regclass
           )
    ),
    'no public view provides a disclosure path to M5 social tables'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_roles AS role_row
          CROSS JOIN unnest(ARRAY[
              'public.friend_codes'::regclass,
              'public.friend_code_rate_limits'::regclass,
              'public.friendships'::regclass,
              'public.friend_revocation_streams'::regclass,
              'public.friend_revocation_events'::regclass
          ]) AS social_table(relation)
          CROSS JOIN unnest(ARRAY[
              'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'
          ]) AS privilege_name(name)
         WHERE role_row.rolname IN ('anon', 'authenticated', 'service_role')
           AND has_table_privilege(role_row.oid, social_table.relation, privilege_name.name)
    ),
    'API roles have no grant on social tables or their discovery data'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_roles AS role_row
         WHERE role_row.rolname IN ('anon', 'authenticated', 'service_role')
           AND has_schema_privilege(role_row.oid, 'm5_private', 'USAGE')
    ),
    'API roles cannot call private M5 helpers outside the public friend-code RPCs'
);

SELECT is(
    ARRAY(
        SELECT format('%s:%s', index_relation.relname, attribute_row.attname)
          FROM pg_index AS index_row
          JOIN pg_class AS index_relation ON index_relation.oid = index_row.indexrelid
          JOIN pg_attribute AS attribute_row
            ON attribute_row.attrelid = index_row.indrelid
           AND attribute_row.attnum = ANY(index_row.indkey)
         WHERE index_row.indrelid = 'public.friend_codes'::regclass
         ORDER BY index_relation.relname, attribute_row.attname
    ),
    ARRAY[
        'friend_codes_code_hash_key:code_hash',
        'friend_codes_pkey:actor_id'
    ],
    'friend-code indexes are limited to the owner and SHA-256 capability address'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_index AS index_row
          JOIN pg_class AS relation_row ON relation_row.oid = index_row.indrelid
          JOIN pg_namespace AS namespace_row ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND pg_get_indexdef(index_row.indexrelid)
               ~* '(^|[^a-z])(email|phone|contact|username|profile)([^a-z]|$)'
    ),
    'the public schema has no index for email, phone, contact, profile, or username discovery'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'public'
           AND column_row.column_name
               ~* '(^|_)(email|phone|contact|username|user_name)(_|$)'
    ),
    'the public schema persists no email, phone, contact, or username search field'
);

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'aCode', public.m5_get_friend_code();
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'aMalformed', public.m5_lookup_friend_code('not-a-friend-code');
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'aSelf', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'aCode')
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'bNamedLookup', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'aCode')
);
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'bMissing', public.m5_lookup_friend_code(repeat('0', 40));
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'bRequest', public.m5_send_friend_request(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'aCode')
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('11111111-1111-4111-8111-111111111111');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'aAccept', public.m5_respond_to_friend_request(
    ((SELECT value ->> 'requestRef' FROM pg_temp.m5_soc003 WHERE name = 'bRequest'))::uuid,
    'accept'
);
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'aBlock', public.m5_block_friend(
    ((SELECT value ->> 'friendRef' FROM pg_temp.m5_soc003 WHERE name = 'aAccept'))::uuid
);
RESET ROLE;

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'bBlocked', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'aCode')
);
RESET ROLE;

INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'rateProbeCode', jsonb_build_object(
    'friendCode',
    upper(lpad(to_hex(candidate_row.value), 40, '0'))
)
  FROM generate_series(0, 31) AS candidate_row(value)
 WHERE NOT EXISTS (
     SELECT 1
       FROM public.friend_codes AS code_row
      WHERE code_row.normalized_code = upper(lpad(to_hex(candidate_row.value), 40, '0'))
 )
 ORDER BY candidate_row.value
 LIMIT 1;

SELECT pg_temp.set_m5_claims('33333333-3333-4333-8333-333333333333');
SET LOCAL ROLE authenticated;
SELECT public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'rateProbeCode')
)
  FROM generate_series(1, 30);
INSERT INTO pg_temp.m5_soc003 (name, value)
SELECT 'cRateLimited', public.m5_lookup_friend_code(
    (SELECT value ->> 'friendCode' FROM pg_temp.m5_soc003 WHERE name = 'rateProbeCode')
);
RESET ROLE;

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'bNamedLookup'),
    jsonb_build_object('status', 'available'),
    'a valid named friend code is the sole available discovery capability'
);

SELECT ok(
    NOT ((SELECT value FROM pg_temp.m5_soc003 WHERE name = 'bNamedLookup') ?| ARRAY[
        'actorId', 'profileId', 'friendCode', 'email', 'phone', 'contact', 'username'
    ]),
    'an available named-code lookup discloses no actor or contact identity'
);

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'aMalformed'),
    jsonb_build_object('status', 'unavailable'),
    'a malformed probe remains generically unavailable'
);

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'aSelf'),
    jsonb_build_object('status', 'unavailable'),
    'a self probe remains generically unavailable'
);

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'bMissing'),
    jsonb_build_object('status', 'unavailable'),
    'a missing named-code probe remains generically unavailable'
);

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'bBlocked'),
    jsonb_build_object('status', 'unavailable'),
    'a blocked named-code probe remains generically unavailable'
);

SELECT is(
    (SELECT value FROM pg_temp.m5_soc003 WHERE name = 'cRateLimited'),
    jsonb_build_object('status', 'unavailable'),
    'a rate-limited named-code probe remains generically unavailable'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_temp.m5_soc003 AS result_row
         WHERE result_row.name IN ('aMalformed', 'aSelf', 'bMissing', 'bBlocked', 'cRateLimited')
           AND (result_row.value - 'status') <> '{}'::jsonb
    ),
    'all unavailable probes have the same status-only opaque response shape'
);

SELECT ok(
    (SELECT attempts FROM public.friend_code_rate_limits
      WHERE actor_id = '33333333-3333-4333-8333-333333333333') > 30,
    'named-code rate limiting is enforced server-side before any disclosure'
);

SELECT pg_temp.set_m5_claims('22222222-2222-4222-8222-222222222222');
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT * FROM public.friend_codes$$,
    '42501', NULL,
    'authenticated callers cannot enumerate friend-code capabilities directly'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
