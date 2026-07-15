-- MIG-001: fresh-schema contract for migrations 0001 through 0004.
-- This file is executed only after the migration runner creates a new local database.
BEGIN;

SELECT plan(26);

CREATE OR REPLACE FUNCTION pg_temp.relation_exists(p_relation text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT to_regclass(p_relation) IS NOT NULL;
$function$;

CREATE OR REPLACE FUNCTION pg_temp.relation_has_columns(
    p_relation text,
    p_columns text[]
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT to_regclass(p_relation) IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
              FROM unnest(p_columns) AS required_column(column_name)
             WHERE NOT EXISTS (
                    SELECT 1
                      FROM pg_attribute AS attribute_row
                     WHERE attribute_row.attrelid = to_regclass(p_relation)
                       AND attribute_row.attname = required_column.column_name
                       AND attribute_row.attnum > 0
                       AND NOT attribute_row.attisdropped
                )
       );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.api_roles_cannot_mutate(p_relation text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT to_regclass(p_relation) IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
              FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) AS expected_role(role_name)
             WHERE NOT EXISTS (
                    SELECT 1
                      FROM pg_roles AS role_row
                     WHERE role_row.rolname = expected_role.role_name
                )
                OR has_table_privilege(expected_role.role_name, p_relation, 'INSERT')
                OR has_table_privilege(expected_role.role_name, p_relation, 'UPDATE')
                OR has_table_privilege(expected_role.role_name, p_relation, 'DELETE')
       );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.has_m3_fixed_path_rpc()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prosecdef
           AND EXISTS (
                SELECT 1
                  FROM unnest(coalesce(procedure_row.proconfig, ARRAY[]::text[])) AS config(setting)
                 WHERE config.setting LIKE 'search_path=pg_catalog%'
                   AND config.setting NOT LIKE '%public%'
           )
    );
$function$;

SELECT ok(pg_temp.relation_exists('public.dataset_manifests'),
    '0001 creates dataset manifests on an empty schema');
SELECT ok(pg_temp.relation_exists('public.mountains'),
    '0001 creates immutable reference mountains on an empty schema');
SELECT ok(pg_temp.relation_exists('public.m2a_auth_checkpoint_policy'),
    '0002 creates the M2A policy table on an empty schema');
SELECT ok(pg_temp.relation_exists('public.m2a_apple_auth_transactions'),
    '0002 creates M2A transactions on an empty schema');
SELECT ok(pg_temp.relation_exists('public.m2a_auth_checkpoint_receipts'),
    '0002 creates M2A receipts on an empty schema');
SELECT ok(to_regprocedure('public.m2a_begin_apple_auth_checkpoint()') IS NOT NULL,
    '0002 retains the anonymous-safe M2A begin RPC');
SELECT ok(to_regprocedure('public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)') IS NOT NULL,
    '0002 retains the authenticated M2A completion RPC');

SELECT ok(pg_temp.relation_exists('public.profiles'),
    '0003 creates profiles');
SELECT ok(pg_temp.relation_exists('public.passport_aggregates'),
    '0003 creates lockable passport aggregates');
SELECT ok(pg_temp.relation_exists('public.mountain_plans'),
    '0003 creates mountain plans');
SELECT ok(pg_temp.relation_exists('public.visit_records'),
    '0003 creates immutable visit records');
SELECT ok(pg_temp.relation_exists('public.stamps'),
    '0003 creates derived stamp projections');
SELECT ok(pg_temp.relation_exists('public.mutation_receipts'),
    '0003 creates actor-bound mutation receipts');
SELECT ok(pg_temp.relation_exists('public.audit_events'),
    '0003 creates audit events');
SELECT ok(pg_temp.relation_has_columns(
    'public.visit_records',
    ARRAY['created_global_version', 'deleted_global_version']
), '0004 versions visit visibility instead of erasing audit history');

SELECT ok(
    (
        SELECT count(*) >= 3
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relkind IN ('r', 'p')
           AND relation_row.relname ~ '(history|change|token|tombstone)'
    ),
    '0004 creates durable history, change, and retention state'
);
SELECT ok(pg_temp.api_roles_cannot_mutate('public.passport_aggregates'),
    'API roles cannot directly mutate aggregate locks');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.mountain_plans'),
    'API roles cannot directly mutate plans');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.visit_records'),
    'API roles cannot directly mutate visits');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.stamps'),
    'API roles cannot directly mutate derived stamps');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.mutation_receipts'),
    'API roles cannot directly mutate receipts');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.audit_events'),
    'API roles cannot directly mutate audit events');
SELECT ok(pg_temp.has_m3_fixed_path_rpc(),
    '0003 or 0004 exposes a fixed-search-path SECURITY DEFINER RPC');

SELECT ok(
    (
        SELECT count(*) = 100
           AND count(DISTINCT mountain_id) = 100
           AND count(DISTINCT ordinal) = 100
           AND min(ordinal) = 1
           AND max(ordinal) = 100
           AND min(dataset_sha256) = '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
           AND max(dataset_sha256) = '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae'
          FROM public.m3_known_mountains
    ),
    'fresh migrations seed the exact authoritative 100-mountain dataset digest'
);
SELECT throws_ok(
    $$SELECT public.m3_self_bootstrap('m2-v1', repeat('0', 64))$$,
    '22023',
    'passport sync API version rejected',
    'bootstrap rejects an outdated API version before issuing a token'
);
SELECT throws_ok(
    $$SELECT public.m3_self_bootstrap('m4-v1', repeat('0', 64))$$,
    '22023',
    'passport sync API version rejected',
    'bootstrap rejects a future unsupported API version before issuing a token'
);
SELECT * FROM finish();
ROLLBACK;
