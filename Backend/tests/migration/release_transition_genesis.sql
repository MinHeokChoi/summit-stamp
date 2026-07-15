-- REL-002-GENESIS: the schema-defined canonical sentinel is the only
-- predecessor for a first release transition.
BEGIN;

SELECT plan(15);


CREATE TEMP TABLE pg_temp.release_genesis_values (
    sentinel_sha text NOT NULL,
    legacy_sentinel_sha text NOT NULL,
    legacy_field_order_sentinel_sha text NOT NULL,
    event_sha text,
    cross_sentinel_sha text,
    cross_event_sha text
) ON COMMIT DROP;
GRANT SELECT ON pg_temp.release_genesis_values TO service_role;

INSERT INTO pg_temp.release_genesis_values (
    sentinel_sha,
    legacy_sentinel_sha,
    legacy_field_order_sentinel_sha
)
VALUES (
    m6_private.release_transition_sentinel_sha(
        'release-genesis', 'v1.2.3', repeat('a', 40), repeat('c', 64), repeat('b', 64)
    ),
    encode(
        extensions.digest(
            convert_to(
                format(
                    '{"commit":%s,"datasetSHA":%s,"migrationSHA":%s,"releaseID":%s,"schemaVersion":1,"tag":%s}',
                    to_json(repeat('a', 40))::text,
                    to_json(repeat('c', 64))::text,
                    to_json(repeat('b', 64))::text,
                    to_json('release-genesis'::text)::text,
                    to_json('v1.2.3'::text)::text
                ),
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    ),
    encode(
        extensions.digest(
            convert_to(
                format(
                    '{"schemaVersion":"m6-release-transition-v1","releaseID":%s,"tag":%s,"commit":%s,"datasetSHA":%s,"migrationSHA":%s}',
                    to_json('release-genesis'::text)::text,
                    to_json('v1.2.3'::text)::text,
                    to_json(repeat('a', 40))::text,
                    to_json(repeat('c', 64))::text,
                    to_json(repeat('b', 64))::text
                ),
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    )
);
SELECT is((SELECT count(*) FROM public.release_transition_events), 0::bigint,
    'a fresh schema has no release transition event');
SELECT ok(to_regclass('public.release_transition_genesis') IS NULL,
    'the migration creates no genesis relation');
SELECT is(
    (SELECT sentinel_sha FROM pg_temp.release_genesis_values),
    encode(
        extensions.digest(
            convert_to(
                format(
                    '{"commit":%s,"datasetSHA":%s,"migrationSHA":%s,"releaseID":%s,"schemaVersion":"m6-release-transition-v1","tag":%s}',
                    to_json(repeat('a', 40))::text,
                    to_json(repeat('c', 64))::text,
                    to_json(repeat('b', 64))::text,
                    to_json('release-genesis'::text)::text,
                    to_json('v1.2.3'::text)::text
                ),
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    ),
    'the sentinel is the exact shared sorted-key canonical release context'
);

SET LOCAL ROLE service_role;
SELECT * FROM public.append_release_transition(
    'release-genesis',
    'predeploy-disabled',
    'v1.2.3',
    repeat('a', 40),
    repeat('b', 64),
    repeat('c', 64),
    'disabled',
    0,
    (SELECT sentinel_sha FROM pg_temp.release_genesis_values),
    repeat('d', 64),
    repeat('e', 64),
    '11111111-1111-4111-8111-111111111112'
);
RESET ROLE;

UPDATE pg_temp.release_genesis_values
   SET event_sha = (
       SELECT event_row.event_sha
         FROM public.release_transition_events AS event_row
        WHERE event_row.release_id = 'release-genesis'
   );

SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.release_transition_events AS event_row
         WHERE event_row.release_id = 'release-genesis'
           AND event_row.sequence = 1
           AND event_row.state = 'predeploy-disabled'
           AND event_row.switch_state = 'disabled'
           AND event_row.actor_id = '00000000-0000-0000-0000-000000000006'
    ),
    'a service controller with no user identity stores the fixed actor and first disabled predeploy'
);
SELECT is(
    (SELECT previous_event_sha FROM public.release_transition_events WHERE release_id = 'release-genesis'),
    (SELECT sentinel_sha FROM pg_temp.release_genesis_values),
    'the first event records the schema-defined sentinel predecessor'
);
SELECT is(
    (SELECT event_sha FROM pg_temp.release_genesis_values),
    encode(
        extensions.digest(
            convert_to(
                format(
                    '{"schemaVersion":"m6-release-transition-v1","releaseID":%s,"sequence":1,"state":%s,"previousEventSHA":%s,"tag":%s,"commit":%s,"migrationSHA":%s,"datasetSHA":%s,"switchState":%s,"approvalSHA":%s,"observedSourceSHA":%s,"actorID":%s,"auditEventID":%s}',
                    to_json('release-genesis'::text)::text,
                    to_json('predeploy-disabled'::text)::text,
                    to_json((SELECT sentinel_sha FROM pg_temp.release_genesis_values))::text,
                    to_json('v1.2.3'::text)::text,
                    to_json(repeat('a', 40))::text,
                    to_json(repeat('b', 64))::text,
                    to_json(repeat('c', 64))::text,
                    to_json('disabled'::text)::text,
                    to_json(repeat('d', 64))::text,
                    to_json(repeat('e', 64))::text,
                    to_json('00000000-0000-0000-0000-000000000006'::text)::text,
                    to_json('11111111-1111-4111-8111-111111111112'::text)::text
                ),
                'UTF8'
            ),
            'sha256'
        ),
        'hex'
    ),
    'the event hash covers the canonical event context and derived actor'
);

SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-wrong-sentinel', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 0,
        (SELECT legacy_sentinel_sha FROM pg_temp.release_genesis_values),
        repeat('f', 64), repeat('0', 64), '22222222-2222-4222-8222-222222222222'
    )$$,
    '22023', NULL::text,
    'a first append rejects the numeric-schema-version sentinel variant'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-wrong-sentinel-order', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 0,
        (SELECT legacy_field_order_sentinel_sha FROM pg_temp.release_genesis_values),
        repeat('1', 64), repeat('2', 64), '21212121-2222-4222-8222-222222222222'
    )$$,
    '22023', NULL::text,
    'a first append rejects the legacy field-order sentinel variant'
);
RESET ROLE;
SELECT is(
    (SELECT count(*) FROM public.release_transition_events
      WHERE release_id IN ('release-wrong-sentinel', 'release-wrong-sentinel-order')),
    0::bigint,
    'sentinel variants create no event'
);

SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-genesis', 'compatibility', 'v2.0.0', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 1,
        (SELECT event_sha FROM pg_temp.release_genesis_values),
        repeat('f', 64), repeat('0', 64), '33333333-3333-4333-8333-333333333333'
    )$$,
    '22023', NULL::text,
    'a later append rejects a tag that differs from the release context'
);
RESET ROLE;
SELECT is(
    (SELECT count(*) FROM public.release_transition_events WHERE release_id = 'release-genesis'),
    1::bigint,
    'a tag mismatch creates no event'
);
SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-genesis', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 0,
        (SELECT sentinel_sha FROM pg_temp.release_genesis_values),
        repeat('1', 64), repeat('2', 64), '77777777-7777-4777-8777-777777777777'
    )$$,
    '22023', NULL::text,
    'an existing release event rejects another sequence-zero first transition'
);
RESET ROLE;

UPDATE pg_temp.release_genesis_values
   SET cross_sentinel_sha = m6_private.release_transition_sentinel_sha(
       'release-cross-origin', 'v1.2.3', repeat('a', 40), repeat('c', 64), repeat('b', 64)
   );

SET LOCAL ROLE service_role;
SELECT * FROM public.append_release_transition(
    'release-cross-origin',
    'predeploy-disabled',
    'v1.2.3',
    repeat('a', 40),
    repeat('b', 64),
    repeat('c', 64),
    'disabled',
    0,
    (SELECT cross_sentinel_sha FROM pg_temp.release_genesis_values),
    repeat('0', 64),
    repeat('1', 64),
    '44444444-4444-4444-8444-444444444444'
);
RESET ROLE;

UPDATE pg_temp.release_genesis_values
   SET cross_event_sha = (
       SELECT event_row.event_sha
         FROM public.release_transition_events AS event_row
        WHERE event_row.release_id = 'release-cross-origin'
   );

SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-genesis', 'compatibility', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 1,
        (SELECT cross_event_sha FROM pg_temp.release_genesis_values),
        repeat('2', 64), repeat('3', 64), '55555555-5555-4555-8555-555555555555'
    )$$,
    '40001', NULL::text,
    'a predecessor from another release fails this release compare-and-swap'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-genesis', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 0,
        (SELECT sentinel_sha FROM pg_temp.release_genesis_values),
        repeat('4', 64), repeat('5', 64), '66666666-6666-4666-8666-666666666666'
    )$$,
    '22023', NULL::text,
    'a concurrently stale first candidate loses after the per-release lock is released'
);
RESET ROLE;
SELECT is(
    (SELECT count(*) FROM public.release_transition_events WHERE release_id = 'release-genesis'),
    1::bigint,
    'cross-release and concurrent-first candidates create no event'
);

SELECT * FROM finish();
ROLLBACK;
