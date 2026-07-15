-- M3-RPC-001: (actor_id, mutation_id) is bound to operation, canonical payload
-- SHA-256, and the exact result returned by the first committed invocation.
BEGIN;
-- These grants are test-local and roll back. Production callers use only
-- m3_apply_passport_mutation, while this fixture exercises internal primitives.
GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_remove_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) TO authenticated;

SELECT plan(12);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m3-idempotency-fixture', 'sha256'), true);

CREATE OR REPLACE FUNCTION pg_temp.set_m3_fixture_claims(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor_id::text,
            'iss', 'https://issuer.invalid/m3',
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

CREATE TEMP TABLE pg_temp.m3_idempotency_results (
    result jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m3_idempotency_results TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
VALUES
    ('idempotency-mountain', repeat('a', 64), 1),
    ('different-payload-mountain', repeat('a', 64), 2);
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
SELECT format('compatibility-mountain-%s', ordinal),
       repeat('a', 64),
       ordinal::smallint
  FROM generate_series(3, 100) AS ordinal;
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT public.passport_add_plan('unknown-mountain', '00000000-0000-4000-8000-000000000000')$$,
    '22023',
    'passport mountain identifier rejected',
    'an unknown MountainID is rejected before any mutation state is created'
);

RESET ROLE;

SELECT ok(
    (SELECT count(*) FROM public.passport_aggregates) = 0
    AND (SELECT count(*) FROM public.passport_mutation_receipts) = 0
    AND (SELECT count(*) FROM public.passport_changes) = 0,
    'an unknown MountainID creates no aggregate, receipt, or change'
);

SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.m3_idempotency_results (result)
SELECT public.passport_add_plan(
    'idempotency-mountain',
    '22222222-2222-4222-8222-222222222222'
);

SELECT is(
    (SELECT result ->> 'operation' FROM pg_temp.m3_idempotency_results),
    'plan_add',
    'the first invocation returns a plan-add result'
);
SELECT is(
    public.passport_add_plan(
        'idempotency-mountain',
        '22222222-2222-4222-8222-222222222222'
    ),
    (SELECT result FROM pg_temp.m3_idempotency_results),
    'an exact retry returns the stored result, not a recomputed projection'
);
SELECT throws_ok(
    $$SELECT public.passport_add_plan('different-payload-mountain', '22222222-2222-4222-8222-222222222222')$$,
    'PT409',
    'mutation id replay does not match original request',
    'a changed canonical payload is rejected for an existing mutation id'
);

RESET ROLE;

SELECT is(
    (SELECT count(*) FROM public.passport_mutation_receipts),
    1::bigint,
    'the retry records exactly one actor-bound mutation receipt'
);
SELECT is(
    (SELECT count(*) FROM public.passport_changes),
    1::bigint,
    'the retry increments global version and appends a change exactly once'
);
SELECT is(
    (SELECT aggregate_row.global_version
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.mountain_id = 'idempotency-mountain'),
    (SELECT (result ->> 'global_version')::bigint FROM pg_temp.m3_idempotency_results),
    'the persisted projection retains the first result version'
);

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$SELECT public.m3_apply_passport_mutation(
        'm2-v1', repeat('a', 64),
        '33333333-3333-4333-8333-333333333331',
        'plan_add', '{"mountainID":"idempotency-mountain"}'::jsonb
    )$$,
    '22023',
    'passport mutation compatibility rejected',
    'an outdated API contract cannot submit a mutation'
);
SELECT throws_ok(
    $$SELECT public.m3_apply_passport_mutation(
        'm3-v1', repeat('b', 64),
        '33333333-3333-4333-8333-333333333332',
        'plan_add', '{"mountainID":"idempotency-mountain"}'::jsonb
    )$$,
    '55000',
    'passport sync known mountain set is unavailable',
    'a mismatched dataset cannot submit a mutation'
);
SELECT throws_ok(
    $$SELECT public.m3_apply_passport_mutation(
        'm3-v1', repeat('a', 64),
        '33333333-3333-4333-8333-333333333333',
        'plan_add', '{"mountainID":"idempotency-mountain","actorID":"11111111-1111-4111-8111-111111111111"}'::jsonb
    )$$,
    '22023',
    'passport mutation payload rejected',
    'unknown or spoofable payload fields are rejected'
);
SELECT is(
    public.m3_apply_passport_mutation(
        'm3-v1', repeat('a', 64),
        '33333333-3333-4333-8333-333333333334',
        'plan_add', '{"mountainID":"different-payload-mountain"}'::jsonb
    ) ->> 'operation',
    'plan_add',
    'the version-bound mutation RPC accepts an exact current contract'
);

RESET ROLE;
SELECT * FROM finish();
ROLLBACK;
