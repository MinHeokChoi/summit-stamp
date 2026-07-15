-- M3-RLS-001: the RPC actor is derived from the Apple-validated JWT, never a
-- caller argument or an actor_id supplied through a base table.
BEGIN;
-- Test-local grant for actor-derivation coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;

SELECT plan(5);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);

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

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
VALUES ('owner-spoof-mountain', repeat('a', 64), 1);
SET LOCAL ROLE authenticated;

SELECT ok(
    (public.passport_add_plan(
        'owner-spoof-mountain',
        '22222222-2222-4222-8222-222222222222'
    ) ->> 'plan_state') = 'active_manual',
    'the authenticated RPC creates a plan for the JWT actor'
);

SELECT throws_ok(
    $$INSERT INTO public.passport_aggregates (actor_id, mountain_id) VALUES ('33333333-3333-4333-8333-333333333333', 'owner-spoof-mountain')$$,
    '42501', NULL,
    'the caller cannot spoof a second owner through base-table DML'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
         WHERE procedure_row.oid = 'public.passport_add_plan(text,uuid)'::regprocedure
           AND 'p_actor_id' = ANY(coalesce(procedure_row.proargnames, ARRAY[]::text[]))
    ),
    'the plan RPC accepts no actor parameter to spoof'
);

RESET ROLE;

SELECT is(
    (SELECT aggregate_row.actor_id
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.mountain_id = 'owner-spoof-mountain'),
    '11111111-1111-4111-8111-111111111111'::uuid,
    'the persisted aggregate owner is derived from the validated JWT subject'
);
SELECT is(
    (SELECT count(*)
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.actor_id = '33333333-3333-4333-8333-333333333333'),
    0::bigint,
    'no spoofed-owner aggregate was persisted'
);

SELECT * FROM finish();
ROLLBACK;
