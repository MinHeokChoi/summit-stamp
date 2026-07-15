-- M3-RPC-002: a plan add and manual visit for the same aggregate serialize on
-- the aggregate row. The visit sees the committed plan, auto-completes it, and
-- final deletion restores only that eligible manual plan.
BEGIN;
-- Test-local grants for internal primitive coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_remove_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) TO authenticated;

SELECT plan(9);

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

CREATE TEMP TABLE pg_temp.m3_race_results (
    label text PRIMARY KEY,
    result jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m3_race_results TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
VALUES ('plan-visit-race-mountain', repeat('a', 64), 1);
SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.m3_race_results (label, result)
SELECT 'plan', public.passport_add_plan(
    'plan-visit-race-mountain',
    '22222222-2222-4222-8222-222222222222'
);
INSERT INTO pg_temp.m3_race_results (label, result)
SELECT 'visit', public.passport_create_manual_visit(
    'plan-visit-race-mountain',
    '33333333-3333-4333-8333-333333333333',
    timestamptz '2026-07-14 12:00:00+00',
    '44444444-4444-4444-8444-444444444444'
);

SELECT is(
    (SELECT result ->> 'plan_state' FROM pg_temp.m3_race_results WHERE label = 'plan'),
    'active_manual',
    'the first serialized mutation creates the manual plan'
);
SELECT is(
    (SELECT result ->> 'plan_state' FROM pg_temp.m3_race_results WHERE label = 'visit'),
    'active_auto_completed',
    'the serialized visit observes and auto-completes the plan'
);
SELECT is(
    (SELECT (result ->> 'aggregate_version')::bigint FROM pg_temp.m3_race_results WHERE label = 'visit'),
    (SELECT (result ->> 'aggregate_version')::bigint + 1 FROM pg_temp.m3_race_results WHERE label = 'plan'),
    'the aggregate version advances once for each serialized mutation'
);

INSERT INTO pg_temp.m3_race_results (label, result)
SELECT 'delete', public.passport_delete_manual_visit(
    '33333333-3333-4333-8333-333333333333',
    '55555555-5555-4555-8555-555555555555'
);

SELECT is(
    (SELECT result ->> 'plan_state' FROM pg_temp.m3_race_results WHERE label = 'delete'),
    'active_manual',
    'deleting the final visit restores the eligible manual plan'
);
SELECT is(
    (SELECT result ->> 'visit_count' FROM pg_temp.m3_race_results WHERE label = 'delete'),
    '0',
    'deleting the final visit derives a zero visit count'
);
SELECT ok(
    (SELECT result -> 'stamp' FROM pg_temp.m3_race_results WHERE label = 'delete') = 'null'::jsonb,
    'deleting the final visit removes the derived stamp'
);

RESET ROLE;

SELECT is(
    (SELECT aggregate_row.aggregate_version
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.mountain_id = 'plan-visit-race-mountain'),
    3::bigint,
    'the aggregate remains the single serialized source of truth'
);
SELECT is(
    (SELECT plan_row.plan_state::text
       FROM public.passport_plans AS plan_row
      WHERE plan_row.mountain_id = 'plan-visit-race-mountain'),
    'active_manual',
    'the durable plan projection matches the restored eligibility'
);
SELECT is(
    (SELECT count(*) FROM public.passport_tombstones WHERE entity_kind = 'visit'),
    1::bigint,
    'manual visit deletion appends a tombstone instead of erasing audit history'
);

SELECT * FROM finish();
ROLLBACK;
