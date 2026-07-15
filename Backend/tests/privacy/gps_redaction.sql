-- M4-GPS-REDACTION-001: raw one-shot GPS samples are not exposed or persisted.
BEGIN;

SELECT plan(11);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m4-redaction', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m4-gps-redaction-fixture', 'sha256'), true);

CREATE OR REPLACE FUNCTION pg_temp.set_m4_redaction_claims(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor_id::text,
            'iss', 'https://issuer.invalid/m4-redaction',
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

CREATE TEMP TABLE pg_temp.m4_gps_redaction_result (
    result jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m4_gps_redaction_result TO authenticated;
CREATE TEMP TABLE pg_temp.m4_gps_redaction_snapshot (
    result jsonb NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m4_gps_redaction_snapshot TO authenticated;

SELECT pg_temp.set_m4_redaction_claims('55555555-5555-4555-8555-555555555555');

SET LOCAL ROLE authenticated;
SELECT set_config(
    'm4.redaction.history_token',
    public.m3_self_bootstrap(
        'm3-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
    ) ->> 'historyToken',
    true
);

INSERT INTO pg_temp.m4_gps_redaction_result (result)
SELECT public.m4_create_gps_visit(
    'm4-v1',
    '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
    current_setting('m4.redaction.history_token'),
    'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
    '60000000-0000-4000-8000-000000000001',
    '2026-07-14 01:00:00+00',
    '61000000-0000-4000-8000-000000000001',
    35.776061466546,
    128.16307418154,
    42.424242,
    clock_timestamp() - interval '1 second'
);
INSERT INTO pg_temp.m4_gps_redaction_snapshot (result)
SELECT public.m3_self_bootstrap(
    'm3-v1',
    '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
);

SELECT ok(
    NOT (
        (SELECT result FROM pg_temp.m4_gps_redaction_result)
        ?| ARRAY['latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at']
    )
    AND (SELECT result::text FROM pg_temp.m4_gps_redaction_result)
        !~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
    AND (SELECT result::text FROM pg_temp.m4_gps_redaction_result)
        !~ '35[.]776061466546|128[.]16307418154|42[.]424242',
    'the successful RPC result exposes no raw GPS fields or values'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.redaction.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '60000000-0000-4000-8000-000000000002',
        '2026-07-14 01:00:01+00',
        '61000000-0000-4000-8000-000000000002',
        0.0,
        0.0,
        42.424242,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_distance_rejected',
    'a rejected sample returns a classified manual fallback without location detail'
);
SELECT throws_ok(
    $$INSERT INTO m3_private.gps_authoritative_summits (
        mountain_id, dataset_sha256, summit_latitude, summit_longitude
    ) VALUES (
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        repeat('a', 64), 0.0, 0.0
    )$$,
    '42501',
    NULL,
    'authenticated callers cannot mutate authoritative summit points directly'
);

RESET ROLE;
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_temp.m4_gps_redaction_snapshot AS bootstrap
         WHERE bootstrap.result::text
                ~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
            OR bootstrap.result::text
                ~ '35[.]776061466546|128[.]16307418154|42[.]424242'
    )
    AND NOT EXISTS (
        SELECT 1
          FROM public.passport_snapshots AS snapshot
         WHERE snapshot.actor_id = '55555555-5555-4555-8555-555555555555'
           AND (
               snapshot.payload::text
                   ~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
               OR snapshot.payload::text
                   ~ '35[.]776061466546|128[.]16307418154|42[.]424242'
           )
    ),
    'a GPS sample never enters a broad-sync response or durable snapshot'
);
SELECT ok(
    NOT has_table_privilege(
        'authenticated',
        'm3_private.gps_authoritative_summits',
        'select,insert,update,delete'
    ),
    'authenticated has no direct read or DML privilege on authoritative summit data'
);
SELECT is(
    (
        SELECT count(*)
          FROM information_schema.columns
         WHERE (table_schema = 'm3_private'
                AND table_name = 'gps_authoritative_summits'
                AND column_name IN (
                    'latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at'
                ))
            OR (table_schema = 'public'
                AND table_name IN (
                    'passport_visits',
                    'passport_aggregates',
                    'passport_stamps',
                    'passport_mutation_receipts',
                    'passport_changes',
                    'passport_snapshots'
                )
                AND column_name IN (
                    'latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at'
                ))
    ),
    0::bigint,
    'no GPS sample column exists in the M4 summit or M3 durable mutation tables'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM public.passport_mutation_receipts AS receipt
         WHERE receipt.mutation_id = '61000000-0000-4000-8000-000000000001'
           AND (
               receipt.result ?| ARRAY[
                   'latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at'
               ]
               OR receipt.result::text
                    ~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
               OR receipt.result::text
                    ~ '35[.]776061466546|128[.]16307418154|42[.]424242'
           )
    ),
    'the idempotency receipt contains no raw GPS fields or values'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM public.passport_changes AS change_row
         WHERE change_row.operation = 'gps_visit_create'
           AND (
               change_row.payload ?| ARRAY[
                   'latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at'
               ]
               OR change_row.result ?| ARRAY[
                   'latitude', 'longitude', 'horizontal_accuracy_m', 'sampled_at'
               ]
               OR change_row.payload::text
                    ~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
               OR change_row.result::text
                    ~ '"(latitude|longitude|horizontal_accuracy_m|sampled_at)"'
               OR change_row.payload::text
                    ~ '35[.]776061466546|128[.]16307418154|42[.]424242'
               OR change_row.result::text
                    ~ '35[.]776061466546|128[.]16307418154|42[.]424242'
           )
    ),
    'the change feed payload and result contain no raw GPS fields or values'
);
SELECT is(
    (SELECT count(*) FROM public.passport_mutation_receipts
      WHERE mutation_id = '61000000-0000-4000-8000-000000000002'),
    0::bigint,
    'a rejected sample leaves no durable receipt containing its raw input'
);
SELECT is(
    (SELECT count(*) FROM public.passport_visits
      WHERE visit_id = '60000000-0000-4000-8000-000000000002'),
    0::bigint,
    'a rejected sample creates no durable visit record'
);
SELECT is(
    (SELECT verification_method::text FROM public.passport_visits
      WHERE visit_id = '60000000-0000-4000-8000-000000000001'),
    'gps_verified',
    'the durable visit records only the advisory gps_verified method'
);

SELECT * FROM finish();
ROLLBACK;
