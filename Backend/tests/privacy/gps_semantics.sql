-- M4-GPS-SEMANTICS-001: the online advisory GPS RPC enforces inclusive
-- distance, accuracy, and sample-age thresholds without weakening M3 authority.
BEGIN;

SELECT plan(27);

INSERT INTO public.m2a_auth_checkpoint_policy (
    singleton,
    expected_issuer_sha256,
    expected_audience_sha256
) VALUES (
    1,
    encode(extensions.digest('https://issuer.invalid/m4', 'sha256'), 'hex'),
    encode(extensions.digest('authenticated', 'sha256'), 'hex')
);
INSERT INTO m3_private.sync_hmac_keys (key_id, key_material, active)
VALUES (1, extensions.digest('m4-gps-semantics-fixture', 'sha256'), true);

CREATE OR REPLACE FUNCTION pg_temp.set_m4_fixture_claims(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    PERFORM set_config(
        'request.jwt.claims',
        jsonb_build_object(
            'sub', p_actor_id::text,
            'iss', 'https://issuer.invalid/m4',
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

CREATE TEMP TABLE pg_temp.m4_gps_results (
    name text PRIMARY KEY,
    result jsonb NOT NULL,
    change_count bigint NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m4_gps_results TO authenticated;
CREATE TEMP TABLE pg_temp.m4_gps_replay_fixture (
    sampled_at timestamptz NOT NULL
) ON COMMIT DROP;
GRANT SELECT, INSERT ON TABLE pg_temp.m4_gps_replay_fixture TO authenticated;

SELECT pg_temp.set_m4_fixture_claims('44444444-4444-4444-8444-444444444444');

SET LOCAL ROLE authenticated;
SELECT set_config(
    'm4.test.history_token',
    public.m3_self_bootstrap(
        'm3-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
    ) ->> 'historyToken',
    true
);

SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm3-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000001',
        '2026-07-14 00:00:00+00',
        '51000000-0000-4000-8000-000000000001',
        35.776061466546, 128.16307418154, 10.0, clock_timestamp()
    )$$,
    '22023',
    'passport GPS API version rejected',
    'only the M4 API envelope is accepted'
);
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        repeat('b', 64),
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000002',
        '2026-07-14 00:00:00+00',
        '51000000-0000-4000-8000-000000000002',
        35.776061466546, 128.16307418154, 10.0, clock_timestamp()
    )$$,
    'PT409',
    'passport GPS capability binding rejected',
    'a history capability cannot be mixed with another dataset binding'
);
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'unknown-mountain',
        '50000000-0000-4000-8000-000000000003',
        '2026-07-14 00:00:00+00',
        '51000000-0000-4000-8000-000000000003',
        35.776061466546, 128.16307418154, 10.0, clock_timestamp()
    )$$,
    '22023',
    'passport mountain identifier rejected',
    'an unknown MountainID is rejected before GPS evaluation'
);

INSERT INTO pg_temp.m4_gps_results (name, result, change_count)
SELECT 'accuracy_zero',
       public.m4_create_gps_visit(
           'm4-v1',
           '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
           current_setting('m4.test.history_token'),
           'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
           '50000000-0000-4000-8000-000000000010',
           '2026-07-14 00:00:10+00',
           '51000000-0000-4000-8000-000000000010',
           35.776061466546, 128.16307418154, 0.0,
           clock_timestamp() - interval '1 second'
       ),
       0::bigint;
SELECT is(
    (SELECT result ->> 'status' FROM pg_temp.m4_gps_results WHERE name = 'accuracy_zero'),
    'gps_verified',
    'zero horizontal accuracy is accepted inclusively'
);

INSERT INTO pg_temp.m4_gps_results (name, result, change_count)
SELECT 'accuracy_hundred',
       public.m4_create_gps_visit(
           'm4-v1',
           '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
           current_setting('m4.test.history_token'),
           'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
           '50000000-0000-4000-8000-000000000011',
           '2026-07-14 00:00:11+00',
           '51000000-0000-4000-8000-000000000011',
           35.776061466546, 128.16307418154, 100.0,
           clock_timestamp() - interval '1 second'
       ),
       0::bigint;
SELECT is(
    (SELECT result ->> 'status' FROM pg_temp.m4_gps_results WHERE name = 'accuracy_hundred'),
    'gps_verified',
    '100 metre horizontal accuracy is accepted inclusively'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000014',
        '2026-07-14 00:00:14+00',
        '51000000-0000-4000-8000-000000000014',
        35.776061466546, 128.16307418154, 99.9,
        clock_timestamp() - interval '1 second'
    ) ->> 'status',
    'gps_verified',
    '99.9 metre horizontal accuracy is accepted just inside the threshold'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000012',
        '2026-07-14 00:00:12+00',
        '51000000-0000-4000-8000-000000000012',
        35.776061466546, 128.16307418154, 100.000001,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_accuracy_rejected',
    'accuracy above 100 metres returns a manual-fallback classification'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000013',
        '2026-07-14 00:00:13+00',
        '51000000-0000-4000-8000-000000000013',
        35.776061466546, 128.16307418154, -0.000001,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_accuracy_rejected',
    'negative horizontal accuracy returns a manual-fallback classification'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000015',
        '2026-07-14 00:00:15+00',
        '51000000-0000-4000-8000-000000000015',
        'NaN'::double precision, 128.16307418154, 10.0,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_sample_invalid',
    'a PostgreSQL NaN latitude returns the invalid-sample manual fallback'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000016',
        '2026-07-14 00:00:16+00',
        '51000000-0000-4000-8000-000000000016',
        35.776061466546, 'Infinity'::double precision, 10.0,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_sample_invalid',
    'a PostgreSQL infinite longitude returns the invalid-sample manual fallback'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000017',
        '2026-07-14 00:00:17+00',
        '51000000-0000-4000-8000-000000000017',
        35.776061466546, 128.16307418154, 'NaN'::double precision,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_accuracy_rejected',
    'a PostgreSQL NaN accuracy returns the accuracy manual fallback'
);

SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000020',
        '2026-07-14 00:00:20+00',
        '51000000-0000-4000-8000-000000000020',
        35.776061466546, 128.16307418154, 10.0,
        statement_timestamp() - interval '120 seconds'
    ) ->> 'status',
    'gps_verified',
    'a sample exactly 120 seconds old is accepted inclusively'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000022',
        '2026-07-14 00:00:22+00',
        '51000000-0000-4000-8000-000000000022',
        35.776061466546, 128.16307418154, 10.0,
        statement_timestamp() - interval '119.9 seconds'
    ) ->> 'status',
    'gps_verified',
    'a sample 119.9 seconds old is accepted just inside the threshold'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000021',
        '2026-07-14 00:00:21+00',
        '51000000-0000-4000-8000-000000000021',
        35.776061466546, 128.16307418154, 10.0,
        clock_timestamp() - interval '121 seconds'
    ) ->> 'reason',
    'gps_sample_age_rejected',
    'a sample older than 120 seconds returns a manual-fallback classification'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000023',
        '2026-07-14 00:00:23+00',
        '51000000-0000-4000-8000-000000000023',
        35.776061466546, 128.16307418154, 10.0,
        statement_timestamp() + interval '1 second'
    ) ->> 'reason',
    'gps_sample_age_rejected',
    'a server-future sample returns the sample-age manual fallback'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000030',
        '2026-07-14 00:00:30+00',
        '51000000-0000-4000-8000-000000000030',
        35.776061466546 + degrees(300.0 / 6371008.8),
        128.16307418154,
        10.0,
        clock_timestamp() - interval '1 second'
    ) ->> 'status',
    'gps_verified',
    'a Haversine distance of exactly 300 metres is accepted inclusively'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000032',
        '2026-07-14 00:00:32+00',
        '51000000-0000-4000-8000-000000000032',
        35.776061466546 + degrees(299.9 / 6371008.8),
        128.16307418154,
        10.0,
        clock_timestamp() - interval '1 second'
    ) ->> 'status',
    'gps_verified',
    'a Haversine distance of 299.9 metres is accepted just inside the threshold'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000031',
        '2026-07-14 00:00:31+00',
        '51000000-0000-4000-8000-000000000031',
        35.776061466546 + degrees(301.0 / 6371008.8),
        128.16307418154,
        10.0,
        clock_timestamp() - interval '1 second'
    ) ->> 'reason',
    'gps_distance_rejected',
    'a Haversine distance above 300 metres returns a manual-fallback classification'
);
INSERT INTO pg_temp.m4_gps_replay_fixture (sampled_at)
VALUES (clock_timestamp() - interval '1 second');

INSERT INTO pg_temp.m4_gps_results (name, result, change_count)
SELECT 'idempotent',
       invocation.result,
       (invocation.result ->> 'global_version')::bigint
  FROM (
      SELECT public.m4_create_gps_visit(
          'm4-v1',
          '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
          current_setting('m4.test.history_token'),
          'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
          '50000000-0000-4000-8000-000000000040',
          '2026-07-14 00:00:40+00',
          '51000000-0000-4000-8000-000000000040',
          35.776061466546, 128.16307418154, 10.0,
          (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
      ) AS result
  ) AS invocation;
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000040',
        '2026-07-14 00:00:40+00',
        '51000000-0000-4000-8000-000000000040',
        35.776061466546, 128.16307418154, 10.0,
        (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
    ),
    (SELECT result FROM pg_temp.m4_gps_results WHERE name = 'idempotent'),
    'an exact GPS retry returns the recorded M3-compatible receipt result'
);
SELECT is(
    public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000040',
        '2026-07-14 00:00:40+00',
        '51000000-0000-4000-8000-000000000040',
        35.7760615, 128.1630742, 20.0,
        (SELECT sampled_at + interval '0.1 second' FROM pg_temp.m4_gps_replay_fixture)
    ),
    (SELECT result FROM pg_temp.m4_gps_results WHERE name = 'idempotent'),
    'changed transient GPS inputs replay the receipt because only the durable visit payload is idempotency-bound'
);
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000040',
        '2026-07-14 00:00:41+00',
        '51000000-0000-4000-8000-000000000040',
        35.776061466546, 128.16307418154, 10.0,
        (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
    )$$,
    'PT409',
    'mutation id replay does not match original request',
    'a changed durable GPS payload cannot reuse the original mutation id'
);

SELECT pg_temp.set_m4_fixture_claims('77777777-7777-4777-8777-777777777777');
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000041',
        '2026-07-14 00:00:41+00',
        '51000000-0000-4000-8000-000000000041',
        35.776061466546, 128.16307418154, 10.0,
        (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
    )$$,
    'PT409',
    'passport sync history request rejected',
    'an actor cannot use another actor''s GPS history capability'
);
SELECT pg_temp.set_m4_fixture_claims('44444444-4444-4444-8444-444444444444');

RESET ROLE;
UPDATE public.m3_history_tokens
   SET compacted_at = clock_timestamp()
 WHERE actor_id = '44444444-4444-4444-8444-444444444444'
   AND compacted_at IS NULL;
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000042',
        '2026-07-14 00:00:42+00',
        '51000000-0000-4000-8000-000000000042',
        35.776061466546, 128.16307418154, 10.0,
        (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
    )$$,
    'PT409',
    'passport sync history request rejected',
    'a compacted GPS history capability is rejected as stale'
);

SELECT set_config(
    'm4.test.history_token',
    public.m3_self_bootstrap(
        'm3-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
    ) ->> 'historyToken',
    true
);

RESET ROLE;
UPDATE public.m3_history_tokens
   SET created_at = clock_timestamp() - interval '91 days',
       expires_at = clock_timestamp() - interval '1 second'
 WHERE actor_id = '44444444-4444-4444-8444-444444444444'
   AND compacted_at IS NULL;
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$SELECT public.m4_create_gps_visit(
        'm4-v1',
        '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae',
        current_setting('m4.test.history_token'),
        'hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77',
        '50000000-0000-4000-8000-000000000043',
        '2026-07-14 00:00:43+00',
        '51000000-0000-4000-8000-000000000043',
        35.776061466546, 128.16307418154, 10.0,
        (SELECT sampled_at FROM pg_temp.m4_gps_replay_fixture)
    )$$,
    'PT409',
    'passport sync history request rejected',
    'an expired GPS history capability is rejected'
);

RESET ROLE;

SELECT is(
    (SELECT count(*) FROM public.passport_changes),
    (SELECT change_count FROM pg_temp.m4_gps_results WHERE name = 'idempotent'),
    'the idempotent retry appends no second M3 change'
);
SELECT is(
    (SELECT verification_method::text
       FROM public.passport_visits
      WHERE visit_id = '50000000-0000-4000-8000-000000000040'),
    'gps_verified',
    'successful GPS recording is stored with the gps_verified method'
);
SELECT is(
    (SELECT count(*) FROM public.passport_mutation_receipts
      WHERE mutation_id IN (
          '51000000-0000-4000-8000-000000000012',
          '51000000-0000-4000-8000-000000000013',
          '51000000-0000-4000-8000-000000000021',
          '51000000-0000-4000-8000-000000000031'
      )),
    0::bigint,
    'manual-fallback GPS failures never create durable mutation receipts'
);

SELECT * FROM finish();
ROLLBACK;
