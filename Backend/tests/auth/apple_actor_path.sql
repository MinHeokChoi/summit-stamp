-- LOCAL FIXTURE CONTRACT TEST ONLY.
-- The claim values, key material, and UUIDs below are non-production fixtures. They do not
-- exercise Apple, Supabase Auth, a Release binary, or TestFlight and cannot satisfy
-- AUTH-APPLE-STAGING; that evidence remains a protected human-run staging gate.
BEGIN;

SELECT plan(24);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m2a', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);

INSERT INTO m2a_private.m2a_actor_correlation_keys (
    key_id,
    key_material,
    active
) VALUES (
    1,
    extensions.digest('local-fixture-m2a-correlation-key', 'sha256'),
    true
);

CREATE OR REPLACE FUNCTION pg_temp.set_m2a_fixture_claims(
    p_actor uuid,
    p_issuer text,
    p_audience text,
    p_provider text,
    p_issued_at bigint DEFAULT ceil(extract(epoch FROM clock_timestamp()))::bigint
)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor::text,
            'iss', p_issuer,
            'aud', p_audience,
            'iat', p_issued_at,
            'role', 'authenticated',
            'app_metadata', jsonb_build_object('provider', p_provider)
        )::text,
        true
    );
    PERFORM set_config('request.jwt.claim.sub', p_actor::text, true);
    PERFORM set_config('request.jwt.claim.role', 'authenticated', true);
    RETURN true;
END;
$function$;

CREATE TEMP TABLE pg_temp.m2a_challenges (
    label text PRIMARY KEY,
    transaction_id uuid NOT NULL,
    nonce text NOT NULL,
    state text NOT NULL,
    expires_at timestamptz NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pg_temp.m2a_challenges TO authenticated;

SET LOCAL ROLE anon;

SELECT results_eq(
    $$SELECT count(*)::bigint FROM public.m2a_begin_apple_auth_checkpoint()$$,
    $$VALUES (1::bigint)$$,
    'begin creates a server-owned pending challenge without an authenticated actor'
);

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        INSERT INTO public.m2a_apple_auth_transactions (
            transaction_id,
            nonce_sha256,
            state_sha256,
            expires_at,
            purge_after
        ) VALUES (
            '00000000-0000-4000-8000-000000000001',
            repeat('a', 64),
            repeat('b', 64),
            clock_timestamp() + interval '10 minutes',
            clock_timestamp() + interval '1 day'
        )
    $$,
    '42501',
    NULL,
    'authenticated clients cannot directly insert checkpoint transactions'
);

SELECT throws_ok(
    $$
        INSERT INTO public.m2a_auth_checkpoint_receipts (
            receipt_id,
            transaction_id,
            actor_correlation_key_id,
            actor_correlation_sha256,
            issuer_sha256,
            audience_sha256,
            provider,
            nonce_sha256,
            state_sha256,
            callback_sha256,
            receipt_sha256,
            status
        ) VALUES (
            '00000000-0000-4000-8000-000000000002',
            '00000000-0000-4000-8000-000000000001',
            1,
            repeat('a', 64),
            repeat('b', 64),
            repeat('c', 64),
            'apple',
            repeat('d', 64),
            repeat('e', 64),
            repeat('f', 64),
            repeat('a', 64),
            'completed'
        )
    $$,
    '42501',
    NULL,
    'authenticated clients cannot directly insert receipts'
);

RESET ROLE;

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_roles AS role_row
         WHERE role_row.rolname = 'service_role'
           AND has_table_privilege(
               role_row.oid,
               'public.m2a_auth_checkpoint_receipts',
               'INSERT'
           )
    ),
    'service_role has no direct receipt insert privilege'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM information_schema.columns AS column_row
         WHERE column_row.table_schema = 'public'
           AND column_row.table_name = 'm2a_auth_checkpoint_receipts'
           AND column_row.column_name = 'actor_id'
    ),
    'receipts persist no raw actor UUID'
);

SELECT throws_ok(
    $$
        UPDATE public.m2a_auth_checkpoint_policy
           SET required_provider = 'apple'
         WHERE singleton = 1
    $$,
    '55000',
    'auth checkpoint policy is immutable',
    'checkpoint policy is immutable after protected configuration'
);

SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
         WHERE procedure_row.oid = 'public.m2a_begin_apple_auth_checkpoint()'::regprocedure
           AND 'search_path=pg_catalog, m2a_private' = ANY(procedure_row.proconfig)
    ),
    'begin SECURITY DEFINER search path excludes public'
);

SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
         WHERE procedure_row.oid = 'public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)'::regprocedure
           AND 'search_path=pg_catalog, m2a_private' = ANY(procedure_row.proconfig)
    ),
    'complete SECURITY DEFINER search path excludes public'
);

SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.m2a_challenges (label, transaction_id, nonce, state, expires_at)
SELECT 'primary', checkpoint.transaction_id, checkpoint.nonce, checkpoint.state, checkpoint.expires_at
  FROM public.m2a_begin_apple_auth_checkpoint() AS checkpoint;

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://wrong-issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '28000',
    'auth checkpoint authentication context rejected',
    'complete rejects an unexpected issuer'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'wrong-audience',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '28000',
    'auth checkpoint authentication context rejected',
    'complete rejects an unexpected audience'
);
SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'google'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '28000',
    'auth checkpoint authentication context rejected',
    'complete rejects a non-Apple provider'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT set_config('request.jwt.claims', '{}', true) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '28000',
    'auth checkpoint authentication context rejected',
    'complete rejects missing JWT claims'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              repeat('z', 64)
          )
         WHERE challenge.label = 'primary'
    $$,
    '22023',
    'auth checkpoint binding rejected',
    'complete rejects a malformed callback digest'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              '00000000-0000-4000-8000-000000000099',
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '22023',
    'auth checkpoint binding rejected',
    'complete rejects a fresh transaction UUID replay'
);

INSERT INTO pg_temp.m2a_challenges (label, transaction_id, nonce, state, expires_at)
SELECT 'replay', checkpoint.transaction_id, checkpoint.nonce, checkpoint.state, checkpoint.expires_at
  FROM public.m2a_begin_apple_auth_checkpoint() AS checkpoint;

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS replay_challenge
          CROSS JOIN pg_temp.m2a_challenges AS primary_challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              replay_challenge.transaction_id,
              replay_challenge.nonce,
              primary_challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE replay_challenge.label = 'replay'
           AND primary_challenge.label = 'primary'
    $$,
    '22023',
    'auth checkpoint binding rejected',
    'complete rejects a state commitment replay on another transaction'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple',
                (
                    SELECT floor(extract(epoch FROM challenge.expires_at - interval '10 minutes'))::bigint
                      FROM pg_temp.m2a_challenges AS challenge
                     WHERE challenge.label = 'primary'
                )
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '28000',
    'auth checkpoint session predates challenge',
    'complete rejects a valid Apple session minted before this challenge'
);
SELECT results_eq(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple',
                (
                    SELECT ceil(extract(epoch FROM challenge.expires_at - interval '10 minutes'))::bigint
                      FROM pg_temp.m2a_challenges AS challenge
                     WHERE challenge.label = 'primary'
                )
            ) AS claims_set
        )
        SELECT checkpoint.status
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          ) AS checkpoint
         WHERE challenge.label = 'primary'
    $$,
    $$VALUES ('completed'::text)$$,
    'complete atomically consumes the server-owned challenge and returns a receipt'
);
RESET ROLE;

CREATE TEMP TABLE pg_temp.m2a_expected_receipt
ON COMMIT DROP
AS
SELECT receipt_row.receipt_id, receipt_row.receipt_sha256
  FROM public.m2a_auth_checkpoint_receipts AS receipt_row
  JOIN pg_temp.m2a_challenges AS challenge
    ON challenge.transaction_id = receipt_row.transaction_id
 WHERE challenge.label = 'primary';

GRANT SELECT ON TABLE pg_temp.m2a_expected_receipt TO authenticated;

SELECT results_eq(
    $$
        SELECT count(*)::bigint
          FROM public.m2a_auth_checkpoint_receipts AS receipt_row
          JOIN pg_temp.m2a_challenges AS challenge
            ON challenge.transaction_id = receipt_row.transaction_id
         WHERE challenge.label = 'primary'
    $$,
    $$VALUES (1::bigint)$$,
    'completion appends exactly one receipt'
);
SET LOCAL ROLE authenticated;

SELECT results_eq(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        ), retry AS (
            SELECT checkpoint.*
              FROM configured
              CROSS JOIN pg_temp.m2a_challenges AS challenge
              CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
                  challenge.transaction_id,
                  challenge.nonce,
                  challenge.state,
                  encode(extensions.digest('callback-primary', 'sha256'), 'hex')
              ) AS checkpoint
             WHERE challenge.label = 'primary'
        )
        SELECT retry.receipt_correlation = receipt_row.receipt_id
               AND retry.receipt_digest = receipt_row.receipt_sha256
          FROM retry
          JOIN pg_temp.m2a_expected_receipt AS receipt_row
            ON receipt_row.receipt_id = retry.receipt_correlation
    $$,
    $$VALUES (true)$$,
    'an exact completion retry returns the original receipt'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '22222222-2222-4222-8222-222222222222',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'primary'
    $$,
    '22023',
    'auth checkpoint binding rejected',
    'a completed challenge retry requires the original actor correlation'
);

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN pg_temp.m2a_challenges AS challenge
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              challenge.transaction_id,
              challenge.nonce,
              challenge.state,
              encode(extensions.digest('callback-primary', 'sha256'), 'hex')
          )
         WHERE challenge.label = 'replay'
    $$,
    '22023',
    'auth checkpoint binding rejected',
    'complete rejects a callback commitment replay'
);

RESET ROLE;

INSERT INTO public.m2a_apple_auth_transactions (
    transaction_id,
    nonce_sha256,
    state_sha256,
    status,
    created_at,
    expires_at,
    purge_after
) VALUES (
    '00000000-0000-4000-8000-000000000080',
    encode(extensions.digest(repeat('1', 64), 'sha256'), 'hex'),
    encode(extensions.digest(repeat('2', 64), 'sha256'), 'hex'),
    'pending',
    clock_timestamp() - interval '11 minutes',
    clock_timestamp() - interval '1 minute',
    clock_timestamp() + interval '1 day'
);
SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$
        WITH configured AS (
            SELECT pg_temp.set_m2a_fixture_claims(
                '11111111-1111-4111-8111-111111111111',
                'https://issuer.invalid/m2a',
                'authenticated',
                'apple'
            ) AS claims_set
        )
        SELECT *
          FROM configured
          CROSS JOIN LATERAL public.m2a_complete_apple_auth_checkpoint(
              '00000000-0000-4000-8000-000000000080',
              repeat('1', 64),
              repeat('2', 64),
              encode(extensions.digest('callback-expired', 'sha256'), 'hex')
          )
    $$,
    '55000',
    'auth checkpoint transaction is unavailable',
    'complete rejects an expired pending challenge'
);

RESET ROLE;

SELECT throws_ok(
    $$
        UPDATE public.m2a_apple_auth_transactions
           SET expires_at = expires_at + interval '1 minute'
         WHERE transaction_id = (
             SELECT transaction_id
               FROM pg_temp.m2a_challenges
              WHERE label = 'replay'
         )
    $$,
    '55000',
    'auth checkpoint transaction bindings are immutable',
    'challenge bindings are immutable even to the table owner'
);

SELECT throws_ok(
    $$
        UPDATE public.m2a_auth_checkpoint_receipts
           SET status = 'completed'
         WHERE transaction_id = (
             SELECT transaction_id
               FROM pg_temp.m2a_challenges
              WHERE label = 'primary'
         )
    $$,
    '55000',
    'auth checkpoint receipts are append-only',
    'receipt rows are immutable even to the table owner'
);

SELECT * FROM finish();
ROLLBACK;
