-- MIG-002: M3 is additive for an M2A client and never substitutes base-table DML for RPCs.
BEGIN;

SELECT plan(16);

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

CREATE OR REPLACE FUNCTION pg_temp.m3_rpc_count()
RETURNS bigint
LANGUAGE sql
STABLE
AS $function$
    SELECT count(*)
      FROM pg_proc AS procedure_row
      JOIN pg_namespace AS namespace_row
        ON namespace_row.oid = procedure_row.pronamespace
     WHERE namespace_row.nspname = 'public'
       AND procedure_row.proname !~ '^m2a_'
       AND procedure_row.prosecdef;
$function$;

CREATE OR REPLACE FUNCTION pg_temp.m3_rpcs_are_hardened()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT pg_temp.m3_rpc_count() >= 4
       AND NOT EXISTS (
            SELECT 1
              FROM pg_proc AS procedure_row
              JOIN pg_namespace AS namespace_row
                ON namespace_row.oid = procedure_row.pronamespace
             WHERE namespace_row.nspname = 'public'
               AND procedure_row.proname !~ '^m2a_'
               AND procedure_row.prosecdef
               AND (
                    NOT EXISTS (
                        SELECT 1
                          FROM unnest(coalesce(procedure_row.proconfig, ARRAY[]::text[])) AS config(setting)
                         WHERE config.setting LIKE 'search_path=pg_catalog%'
                           AND config.setting NOT LIKE '%public%'
                    )
                    OR has_function_privilege('public', procedure_row.oid, 'EXECUTE')
               )
       );
$function$;

SELECT ok(to_regprocedure('public.m2a_begin_apple_auth_checkpoint()') IS NOT NULL,
    'M3 retains the old anonymous M2A begin RPC');
SELECT ok(to_regprocedure('public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)') IS NOT NULL,
    'M3 retains the old authenticated M2A completion RPC');
SELECT ok(has_function_privilege('anon', 'public.m2a_begin_apple_auth_checkpoint()'::regprocedure, 'EXECUTE'),
    'an old anonymous client still has execute on M2A begin');
SELECT ok(has_function_privilege('authenticated', 'public.m2a_begin_apple_auth_checkpoint()'::regprocedure, 'EXECUTE'),
    'an old authenticated client still has execute on M2A begin');
SELECT ok(has_function_privilege(
    'authenticated',
    'public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)'::regprocedure,
    'EXECUTE'
), 'an old authenticated client still has execute on M2A completion');

SET LOCAL ROLE anon;
SELECT results_eq(
    $$SELECT count(*)::bigint FROM public.m2a_begin_apple_auth_checkpoint()$$,
    $$VALUES (1::bigint)$$,
    'an old anonymous client can still start an M2A transaction through its RPC'
);
RESET ROLE;

SELECT ok(pg_temp.api_roles_cannot_mutate('public.passport_aggregates'),
    'old and new API roles cannot directly mutate aggregate locks');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.mountain_plans'),
    'old and new API roles cannot directly mutate plans');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.visit_records'),
    'old and new API roles cannot directly mutate immutable visits');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.stamps'),
    'old and new API roles cannot directly mutate derived stamps');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.mutation_receipts'),
    'old and new API roles cannot directly mutate mutation receipts');
SELECT ok(pg_temp.api_roles_cannot_mutate('public.audit_events'),
    'old and new API roles cannot directly mutate audit events');

SELECT cmp_ok(pg_temp.m3_rpc_count(), '>=', 4::bigint,
    'M3 exposes separate SECURITY DEFINER RPCs instead of granting direct DML');
SELECT ok(pg_temp.m3_rpcs_are_hardened(),
    'every M3 public SECURITY DEFINER RPC has a fixed non-public search path and no PUBLIC execute');
SELECT ok(
    (
        SELECT count(*) >= 4
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prosecdef
           AND has_function_privilege('authenticated', procedure_row.oid, 'EXECUTE')
    ),
    'authenticated clients receive the narrow M3 RPC surface rather than table privileges'
);
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prosecdef
           AND has_function_privilege('anon', procedure_row.oid, 'EXECUTE')
    ),
    'anonymous clients receive no M3 mutation or self-read RPC access'
);

SELECT * FROM finish();
ROLLBACK;
