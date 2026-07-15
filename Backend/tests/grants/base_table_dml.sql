-- M3-GRANTS-001: authenticated clients mutate passport state only through RPCs.
BEGIN;

SELECT plan(10);

SET LOCAL ROLE authenticated;

SELECT throws_ok(
    $$INSERT INTO public.profiles (actor_id) VALUES ('11111111-1111-4111-8111-111111111111')$$,
    '42501', NULL,
    'authenticated clients cannot insert actor roots directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_aggregates (actor_id, mountain_id) VALUES ('11111111-1111-4111-8111-111111111111', 'opaque-mountain')$$,
    '42501', NULL,
    'authenticated clients cannot insert aggregate locks directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_plans (actor_id, mountain_id, plan_state, aggregate_version, global_version) VALUES ('11111111-1111-4111-8111-111111111111', 'opaque-mountain', 'active_manual', 1, 1)$$,
    '42501', NULL,
    'authenticated clients cannot insert plans directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_visits (visit_id, actor_id, mountain_id, visited_at, recorded_at, verification_method, created_aggregate_version, created_global_version) VALUES ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111', 'opaque-mountain', clock_timestamp(), clock_timestamp(), 'manual', 1, 1)$$,
    '42501', NULL,
    'authenticated clients cannot insert immutable visits directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_stamps (actor_id, mountain_id, source_visit_id, earned_at, verification_method, aggregate_version, global_version) VALUES ('11111111-1111-4111-8111-111111111111', 'opaque-mountain', '22222222-2222-4222-8222-222222222222', clock_timestamp(), 'manual', 1, 1)$$,
    '42501', NULL,
    'authenticated clients cannot insert derived stamps directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_tombstones (actor_id, mountain_id, entity_kind, entity_id, aggregate_version, global_version, payload, deleted_at, expires_at) VALUES ('11111111-1111-4111-8111-111111111111', 'opaque-mountain', 'visit', '22222222-2222-4222-8222-222222222222', 1, 1, '{}'::jsonb, clock_timestamp(), clock_timestamp() + interval '90 days')$$,
    '42501', NULL,
    'authenticated clients cannot append tombstones directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_mutation_receipts (actor_id, mutation_id, operation, payload_sha256, result, created_at, expires_at) VALUES ('11111111-1111-4111-8111-111111111111', '33333333-3333-4333-8333-333333333333', 'plan_add', repeat('a', 64), '{}'::jsonb, clock_timestamp(), clock_timestamp() + interval '90 days')$$,
    '42501', NULL,
    'authenticated clients cannot append mutation receipts directly'
);
SELECT throws_ok(
    $$UPDATE public.passport_global_state SET global_version = 99 WHERE actor_id = '11111111-1111-4111-8111-111111111111'$$,
    '42501', NULL,
    'authenticated clients cannot advance the global version directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_snapshots (actor_id, snapshot_version, global_version, payload, expires_at) VALUES ('11111111-1111-4111-8111-111111111111', 1, 1, '{}'::jsonb, clock_timestamp() + interval '90 days')$$,
    '42501', NULL,
    'authenticated clients cannot create snapshots directly'
);
SELECT throws_ok(
    $$INSERT INTO public.passport_changes (actor_id, mountain_id, operation, aggregate_version, global_version, payload, result, created_at, expires_at) VALUES ('11111111-1111-4111-8111-111111111111', 'opaque-mountain', 'plan_add', 1, 1, '{}'::jsonb, '{}'::jsonb, clock_timestamp(), clock_timestamp() + interval '90 days')$$,
    '42501', NULL,
    'authenticated clients cannot append change facts directly'
);

RESET ROLE;
SELECT * FROM finish();
ROLLBACK;
