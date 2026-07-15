-- M3-RPC-003: last-delete/create and two-delete submissions serialize through
-- the aggregate row, preserving the derived count and stamp projection.
BEGIN;
-- Test-local grants for internal primitive coverage; rolled back below.
GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_remove_plan(text, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) TO authenticated;

SELECT plan(8);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m3-delete-create', 'sha256'), 'hex'),
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
            'iss', 'https://issuer.invalid/m3-delete-create',
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

CREATE TEMP TABLE pg_temp.m3_delete_create_results (
    label text PRIMARY KEY,
    result jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m3_delete_create_results TO authenticated;

SELECT pg_temp.set_m3_fixture_claims('11111111-1111-4111-8111-111111111111');

DELETE FROM public.m3_known_mountains;
INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
VALUES
    ('last-delete-create-mountain', repeat('a', 64), 1),
    ('two-delete-mountain', repeat('a', 64), 2);
SET LOCAL ROLE authenticated;

INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'last-create-initial', public.passport_create_manual_visit(
    'last-delete-create-mountain',
    '00000000-0000-4000-8000-000000000101',
    timestamptz '2026-07-14 12:00:00+00',
    '00000000-0000-4000-8000-000000001101'
);
INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'last-delete', public.passport_delete_manual_visit(
    '00000000-0000-4000-8000-000000000101',
    '00000000-0000-4000-8000-000000001102'
);
INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'last-create', public.passport_create_manual_visit(
    'last-delete-create-mountain',
    '00000000-0000-4000-8000-000000000102',
    timestamptz '2026-07-14 13:00:00+00',
    '00000000-0000-4000-8000-000000001103'
);

INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'two-delete-create-one', public.passport_create_manual_visit(
    'two-delete-mountain',
    '00000000-0000-4000-8000-000000000201',
    timestamptz '2026-07-14 14:00:00+00',
    '00000000-0000-4000-8000-000000001201'
);
INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'two-delete-create-two', public.passport_create_manual_visit(
    'two-delete-mountain',
    '00000000-0000-4000-8000-000000000202',
    timestamptz '2026-07-14 15:00:00+00',
    '00000000-0000-4000-8000-000000001202'
);
INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'two-delete-first', public.passport_delete_manual_visit(
    '00000000-0000-4000-8000-000000000201',
    '00000000-0000-4000-8000-000000001203'
);
INSERT INTO pg_temp.m3_delete_create_results (label, result)
SELECT 'two-delete-second', public.passport_delete_manual_visit(
    '00000000-0000-4000-8000-000000000202',
    '00000000-0000-4000-8000-000000001204'
);

SELECT is(
    (SELECT result ->> 'visit_count'
       FROM pg_temp.m3_delete_create_results
      WHERE label = 'last-delete'),
    '0',
    'the serialized last delete derives a zero visit count'
);
SELECT ok(
    (SELECT result -> 'stamp' = 'null'::jsonb
       FROM pg_temp.m3_delete_create_results
      WHERE label = 'last-delete'),
    'the serialized last delete clears the derived stamp'
);
SELECT is(
    (SELECT result ->> 'visit_count'
       FROM pg_temp.m3_delete_create_results
      WHERE label = 'last-create'),
    '1',
    'a create serialized after the last delete derives one active visit'
);
SELECT is(
    (SELECT (created.result ->> 'aggregate_version')::bigint
       FROM pg_temp.m3_delete_create_results AS created
       JOIN pg_temp.m3_delete_create_results AS deleted ON deleted.label = 'last-delete'
      WHERE created.label = 'last-create'),
    (SELECT (result ->> 'aggregate_version')::bigint + 1
       FROM pg_temp.m3_delete_create_results
      WHERE label = 'last-delete'),
    'last-delete/create submissions advance the aggregate exactly once in serialized order'
);

RESET ROLE;

SELECT is(
    (SELECT aggregate_row.visit_count
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.actor_id = '11111111-1111-4111-8111-111111111111'
        AND aggregate_row.mountain_id = 'last-delete-create-mountain'),
    1,
    'the last-delete/create aggregate retains exactly the recreated visit'
);
SELECT is(
    (SELECT aggregate_row.stamp_source_visit_id
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.actor_id = '11111111-1111-4111-8111-111111111111'
        AND aggregate_row.mountain_id = 'last-delete-create-mountain'),
    '00000000-0000-4000-8000-000000000102'::uuid,
    'the recreated visit becomes the canonical stamp source'
);
SELECT ok(
    (SELECT (first_delete.result ->> 'visit_count') = '1'
            AND (second_delete.result ->> 'visit_count') = '0'
            AND (second_delete.result ->> 'aggregate_version')::bigint
                = (first_delete.result ->> 'aggregate_version')::bigint + 1
       FROM pg_temp.m3_delete_create_results AS first_delete
       JOIN pg_temp.m3_delete_create_results AS second_delete
         ON second_delete.label = 'two-delete-second'
      WHERE first_delete.label = 'two-delete-first'),
    'two deletes serialize so the second observes the first deletion'
);
SELECT ok(
    (SELECT aggregate_row.visit_count = 0
            AND aggregate_row.stamp_source_visit_id IS NULL
            AND aggregate_row.stamp_earned_at IS NULL
            AND aggregate_row.stamp_verification_method IS NULL
            AND (
                SELECT count(*)
                  FROM public.passport_visits AS visit_row
                 WHERE visit_row.actor_id = aggregate_row.actor_id
                   AND visit_row.mountain_id = aggregate_row.mountain_id
                   AND visit_row.deleted_global_version IS NOT NULL
            ) = 2
            AND (
                SELECT count(*)
                  FROM public.passport_tombstones AS tombstone_row
                 WHERE tombstone_row.actor_id = aggregate_row.actor_id
                   AND tombstone_row.mountain_id = aggregate_row.mountain_id
                   AND tombstone_row.entity_kind = 'visit'
            ) = 2
       FROM public.passport_aggregates AS aggregate_row
      WHERE aggregate_row.actor_id = '11111111-1111-4111-8111-111111111111'
        AND aggregate_row.mountain_id = 'two-delete-mountain'),
    'two serialized deletes leave a canonical empty aggregate and two audit tombstones'
);

SELECT * FROM finish();
ROLLBACK;
