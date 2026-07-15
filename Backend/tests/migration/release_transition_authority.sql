-- REL-TRANSITION-AUTHORITY: only the service-role controller can append the
-- authoritative release chain; release evidence remains immutable afterward.
BEGIN;
SELECT plan(19);

CREATE OR REPLACE FUNCTION pg_temp.api_roles_cannot_mutate_release_events()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) AS expected_role(role_name)
         WHERE NOT EXISTS (
                SELECT 1 FROM pg_roles AS role_row
                 WHERE role_row.rolname = expected_role.role_name
            )
            OR has_table_privilege(expected_role.role_name, 'public.release_transition_events', 'INSERT')
            OR has_table_privilege(expected_role.role_name, 'public.release_transition_events', 'UPDATE')
            OR has_table_privilege(expected_role.role_name, 'public.release_transition_events', 'DELETE')
    );
$function$;

CREATE TEMP TABLE pg_temp.release_authority_values (
    sentinel_sha text NOT NULL,
    event_sha text
) ON COMMIT DROP;
GRANT SELECT ON pg_temp.release_authority_values TO authenticated, service_role;

INSERT INTO pg_temp.release_authority_values (sentinel_sha)
VALUES (
    m6_private.release_transition_sentinel_sha(
        'release-authority', 'v1.2.3', repeat('a', 40), repeat('c', 64), repeat('b', 64)
    )
);

SELECT ok(to_regclass('public.release_transition_events') IS NOT NULL,
    'the authoritative release transition relation exists');
SELECT ok(
    (
        SELECT array_agg(attribute_row.attname::text ORDER BY attribute_row.attnum)
          FROM pg_attribute AS attribute_row
         WHERE attribute_row.attrelid = 'public.release_transition_events'::regclass
           AND attribute_row.attnum > 0
           AND NOT attribute_row.attisdropped
    ) = ARRAY[
        'release_id', 'sequence', 'state', 'previous_event_sha', 'event_sha',
        'tag', 'commit_sha', 'migration_sha', 'dataset_sha', 'switch_state',
        'approval_sha', 'observed_source_sha', 'actor_id', 'audit_event_id', 'created_at'
    ],
    'the authoritative relation contains only the declared release event context'
);
SELECT ok(
    (SELECT relation_row.relrowsecurity
       AND relation_row.relforcerowsecurity
       FROM pg_class AS relation_row
      WHERE relation_row.oid = 'public.release_transition_events'::regclass),
    'release transition events force row-level security'
);
SELECT ok(pg_temp.api_roles_cannot_mutate_release_events(),
    'API roles have no direct insert, update, or delete privilege on release events'
);
SELECT ok(
    to_regprocedure(
        'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'
    ) IS NOT NULL,
    'the only public release writer has the exact narrow RPC signature'
);
SELECT ok(
    (
        SELECT procedure_row.prosecdef
           AND procedure_row.proconfig IS NOT DISTINCT FROM ARRAY[
               'search_path=pg_catalog, m2a_private, m3_private, m6_private, extensions'
           ]
          FROM pg_proc AS procedure_row
         WHERE procedure_row.oid = to_regprocedure(
             'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'
         )
    ),
    'the public writer is security definer with a fixed trusted search path'
);
SELECT ok(
    NOT has_function_privilege(
        'public',
        'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'::regprocedure,
        'EXECUTE'
    )
    AND NOT has_function_privilege(
        'authenticated',
        'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'::regprocedure,
        'EXECUTE'
    )
    AND NOT has_function_privilege(
        'anon',
        'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'::regprocedure,
        'EXECUTE'
    )
    AND has_function_privilege(
        'service_role',
        'public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid)'::regprocedure,
        'EXECUTE'
    ),
    'only service_role receives execute on the release append RPC'
);
SELECT ok(
    NOT has_function_privilege(
        'authenticated',
        'm6_private.release_transition_sentinel_sha(text,text,text,text,text)'::regprocedure,
        'EXECUTE'
    )
    AND NOT has_function_privilege(
        'service_role',
        'm6_private.release_transition_sentinel_sha(text,text,text,text,text)'::regprocedure,
        'EXECUTE'
    )
    AND NOT has_function_privilege(
        'authenticated',
        'm6_private.release_transition_event_sha(text,bigint,text,text,text,text,text,text,text,text,text,uuid,uuid)'::regprocedure,
        'EXECUTE'
    )
    AND NOT has_function_privilege(
        'service_role',
        'm6_private.release_transition_event_sha(text,bigint,text,text,text,text,text,text,text,text,text,uuid,uuid)'::regprocedure,
        'EXECUTE'
    ),
    'API roles cannot call private hashing helpers as alternate writers'
);
SELECT ok(to_regclass('public.release_transition_genesis') IS NULL,
    'there is no genesis manifest or writable genesis relation');

SELECT set_config('request.jwt.claims', '{}', true);
SELECT set_config('request.jwt.claim.sub', '', true);
SELECT is(auth.uid(), NULL::uuid,
    'the protected controller invocation has no authenticated user actor');
SET LOCAL ROLE authenticated;
SELECT throws_ok(
    $$INSERT INTO public.release_transition_events (release_id, sequence)
      VALUES ('release-direct-write', 1)$$,
    '42501', NULL,
    'authenticated cannot directly insert a release transition event'
);
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-authority', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 0,
        (SELECT sentinel_sha FROM pg_temp.release_authority_values),
        repeat('d', 64), repeat('e', 64), '11111111-1111-4111-8111-111111111112'
    )$$,
    '42501', NULL,
    'authenticated cannot invoke the service-only release transition RPC'
);
RESET ROLE;
SET LOCAL ROLE service_role;
SELECT * FROM public.append_release_transition(
    'release-authority', 'predeploy-disabled', 'v1.2.3', repeat('a', 40),
    repeat('b', 64), repeat('c', 64), 'disabled', 0,
    (SELECT sentinel_sha FROM pg_temp.release_authority_values),
    repeat('d', 64), repeat('e', 64), '11111111-1111-4111-8111-111111111112'
);
RESET ROLE;

UPDATE pg_temp.release_authority_values
   SET event_sha = (
       SELECT event_row.event_sha
         FROM public.release_transition_events AS event_row
        WHERE event_row.release_id = 'release-authority'
   );

SELECT ok(
    EXISTS (
        SELECT 1
          FROM public.release_transition_events AS event_row
         WHERE event_row.release_id = 'release-authority'
           AND event_row.actor_id = '00000000-0000-0000-0000-000000000006'
           AND event_row.audit_event_id = '11111111-1111-4111-8111-111111111112'
    ),
    'the service controller records its fixed identity without a caller JWT actor'
);
SELECT throws_ok(
    $$UPDATE public.release_transition_events
         SET approval_sha = repeat('0', 64)
       WHERE release_id = 'release-authority'$$,
    '55000', NULL,
    'an appended approval and observed context cannot be rewritten'
);
SELECT throws_ok(
    $$DELETE FROM public.release_transition_events
       WHERE release_id = 'release-authority'$$,
    '55000', NULL,
    'an appended release event cannot be deleted'
);

SET LOCAL ROLE service_role;
SELECT throws_ok(
    $$SELECT * FROM public.append_release_transition(
        'release-authority', 'compatibility', 'v1.2.3', repeat('a', 40),
        repeat('b', 64), repeat('c', 64), 'disabled', 1,
        (SELECT event_sha FROM pg_temp.release_authority_values),
        repeat('d', 64), repeat('0', 64), '11111111-1111-4111-8111-111111111113'
    )$$,
    '22023', NULL,
    'a consumed approval SHA cannot be replayed by a later state'
);
RESET ROLE;

SELECT is(
    (SELECT count(*) FROM public.release_transition_events WHERE release_id = 'release-authority'),
    1::bigint,
    'direct-write, mutation, authenticated, and approval replay attempts leave one immutable event'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_policy AS policy_row
         WHERE policy_row.polrelid = 'public.release_transition_events'::regclass
    ),
    'no RLS policy grants an alternate read or write path'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_trigger AS trigger_row
         WHERE trigger_row.tgrelid = 'public.release_transition_events'::regclass
           AND trigger_row.tgname = 'release_transition_events_append_only'
           AND NOT trigger_row.tgisinternal
    ),
    'an append-only trigger protects evidence even for relation owners'
);

SELECT * FROM finish();
ROLLBACK;
