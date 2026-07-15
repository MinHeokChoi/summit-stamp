-- MIG-003: local retention-source contract. It validates the deterministic 90-day
-- resync boundary and audit-preservation mechanism; it does not represent a protected drill.
BEGIN;

SELECT plan(12);

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

CREATE OR REPLACE FUNCTION pg_temp.history_state_relation_count()
RETURNS bigint
LANGUAGE sql
STABLE
AS $function$
    SELECT count(*)
      FROM pg_class AS relation_row
      JOIN pg_namespace AS namespace_row
        ON namespace_row.oid = relation_row.relnamespace
     WHERE namespace_row.nspname = 'public'
       AND relation_row.relkind IN ('r', 'p')
       AND relation_row.relname ~ '(history|change|token|tombstone)';
$function$;

CREATE OR REPLACE FUNCTION pg_temp.retention_guard_exists()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname IN ('public', 'm3_private')
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prokind IN ('f', 'p')
           AND pg_get_functiondef(procedure_row.oid) ~* $$interval[[:space:]]+'90[[:space:]]+days'$$
           AND pg_get_functiondef(procedure_row.oid) ~* 'resync'
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.retention_guard_preserves_visits()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname IN ('public', 'm3_private')
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prokind IN ('f', 'p')
           AND pg_get_functiondef(procedure_row.oid) ~* $$interval[[:space:]]+'90[[:space:]]+days'$$
           AND pg_get_functiondef(procedure_row.oid) ~* 'resync'
           AND pg_get_functiondef(procedure_row.oid) !~* $$delete[[:space:]]+from[[:space:]]+public\.passport_visits$$
    );
$function$;

SELECT ok(
    to_regclass('public.passport_visits') IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
          FROM unnest(ARRAY['created_global_version', 'deleted_global_version']) AS required_column(column_name)
         WHERE NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS attribute_row
                 WHERE attribute_row.attrelid = 'public.passport_visits'::regclass
                   AND attribute_row.attname = required_column.column_name
                   AND attribute_row.attnum > 0
                   AND NOT attribute_row.attisdropped
            )
    ),
    'visit history uses created and deleted global versions for snapshot visibility'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relname = 'passport_visits'
           AND relation_row.relrowsecurity
    ),
    'visit records retain row-level security after retention support is added'
);
SELECT ok(pg_temp.api_roles_cannot_mutate('public.passport_visits'),
    'API roles cannot erase or rewrite immutable visits directly');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.passport_changes'),
    'API roles cannot erase or rewrite audit events directly');
SELECT cmp_ok(pg_temp.history_state_relation_count(), '>=', 3::bigint,
    'history, change, token, and tombstone retention state is durable schema, not client state');
SELECT ok(pg_temp.retention_guard_exists(),
    'a public sync RPC contains the exact 90-day resync guard');
SELECT ok(pg_temp.retention_guard_preserves_visits(),
    'the 90-day resync guard does not delete immutable visit records');
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relkind IN ('r', 'p')
           AND relation_row.relname ~ '(history|change|token|tombstone)'
           AND (
                has_table_privilege('anon', relation_row.oid, 'INSERT')
                OR has_table_privilege('anon', relation_row.oid, 'UPDATE')
                OR has_table_privilege('anon', relation_row.oid, 'DELETE')
                OR has_table_privilege('authenticated', relation_row.oid, 'INSERT')
                OR has_table_privilege('authenticated', relation_row.oid, 'UPDATE')
                OR has_table_privilege('authenticated', relation_row.oid, 'DELETE')
           )
    ),
    'history retention state cannot be directly rewritten by API roles'
);
SELECT ok(
    EXISTS (
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
    ),
    'retention and resync state is reached through a fixed-path RPC'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_attribute AS attribute_row
          JOIN pg_class AS relation_row
            ON relation_row.oid = attribute_row.attrelid
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relkind IN ('r', 'p')
           AND relation_row.relname ~ '(history|change|token|tombstone)'
           AND attribute_row.attname IN ('created_at', 'expires_at', 'compacted_at')
           AND attribute_row.attnum > 0
           AND NOT attribute_row.attisdropped
    ),
    'retention state records a server-side retention boundary timestamp'
);
SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relname = 'passport_changes'
           AND relation_row.relrowsecurity
    ),
    'audit events stay protected by row-level security while retained history compacts'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_class AS relation_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = relation_row.relnamespace
         WHERE namespace_row.nspname = 'public'
           AND relation_row.relkind IN ('r', 'p')
           AND relation_row.relname ~ '(history|change|token|tombstone)'
           AND NOT relation_row.relrowsecurity
    ),
    'all durable retention state remains covered by row-level security'
);

SELECT * FROM finish();
ROLLBACK;
