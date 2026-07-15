-- MIG-004: forward migrations are additive while release predeploy remains disabled.
-- The isolated migration fixture must contain schema only, not a release transition or user data.
BEGIN;

SELECT plan(15);

CREATE OR REPLACE FUNCTION pg_temp.all_relations_exist(p_relations text[])
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM unnest(p_relations) AS required_relation(relation_name)
         WHERE to_regclass(required_relation.relation_name) IS NULL
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.all_relations_have_rls(p_relations text[])
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT pg_temp.all_relations_exist(p_relations)
       AND NOT EXISTS (
            SELECT 1
              FROM unnest(p_relations) AS required_relation(relation_name)
              JOIN pg_class AS relation_row
                ON relation_row.oid = to_regclass(required_relation.relation_name)
             WHERE NOT relation_row.relrowsecurity
       );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.api_roles_cannot_mutate(p_relations text[])
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT pg_temp.all_relations_exist(p_relations)
       AND NOT EXISTS (
            SELECT 1
              FROM unnest(p_relations) AS required_relation(relation_name)
              CROSS JOIN unnest(ARRAY['anon', 'authenticated', 'service_role']) AS expected_role(role_name)
             WHERE NOT EXISTS (
                    SELECT 1
                      FROM pg_roles AS role_row
                     WHERE role_row.rolname = expected_role.role_name
                )
                OR has_table_privilege(expected_role.role_name, required_relation.relation_name, 'INSERT')
                OR has_table_privilege(expected_role.role_name, required_relation.relation_name, 'UPDATE')
                OR has_table_privilege(expected_role.role_name, required_relation.relation_name, 'DELETE')
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

SELECT ok(to_regclass('public.dataset_manifests') IS NOT NULL,
    'predeploy-disabled migration retains the 0001 manifest table');
SELECT ok(to_regclass('public.mountains') IS NOT NULL,
    'predeploy-disabled migration retains the 0001 immutable mountain table');
SELECT ok(to_regclass('public.m2a_auth_checkpoint_policy') IS NOT NULL,
    'predeploy-disabled migration retains the 0002 policy table');
SELECT ok(to_regprocedure('public.m2a_begin_apple_auth_checkpoint()') IS NOT NULL,
    'predeploy-disabled migration retains the old anonymous M2A RPC');
SELECT ok(to_regprocedure('public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)') IS NOT NULL,
    'predeploy-disabled migration retains the old authenticated M2A RPC');
SELECT ok(has_function_privilege('anon', 'public.m2a_begin_apple_auth_checkpoint()'::regprocedure, 'EXECUTE'),
    'predeploy-disabled migration does not revoke old anonymous M2A access');

SET LOCAL ROLE anon;
SELECT results_eq(
    $$SELECT count(*)::bigint FROM public.m2a_begin_apple_auth_checkpoint()$$,
    $$VALUES (1::bigint)$$,
    'an old client continues through the additive predeploy-disabled migration'
);
RESET ROLE;

SELECT ok(pg_temp.all_relations_exist(ARRAY[
    'public.profiles',
    'public.passport_aggregates',
    'public.mountain_plans',
    'public.visit_records',
    'public.stamps',
    'public.mutation_receipts',
    'public.audit_events'
]), '0003 domain relations are present without replacing M0 through M2 relations');
SELECT ok(pg_temp.all_relations_have_rls(ARRAY[
    'public.profiles',
    'public.passport_aggregates',
    'public.passport_plans',
    'public.passport_visits',
    'public.passport_stamps',
    'public.passport_mutation_receipts',
    'public.passport_changes'
]), 'all additive M3 domain relations have row-level security enabled');
SELECT ok(pg_temp.api_roles_cannot_mutate(ARRAY[
    'public.passport_aggregates',
    'public.passport_plans',
    'public.passport_visits',
    'public.passport_stamps',
    'public.passport_mutation_receipts',
    'public.passport_changes'
]), 'predeploy-disabled migration grants no direct API DML on new domain state');
SELECT cmp_ok(pg_temp.m3_rpc_count(), '>=', 4::bigint,
    'new mutation capability is supplied by additive RPCs before deployment');
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM pg_proc AS procedure_row
          JOIN pg_namespace AS namespace_row
            ON namespace_row.oid = procedure_row.pronamespace
         WHERE namespace_row.nspname = 'public'
           AND procedure_row.proname !~ '^m2a_'
           AND procedure_row.prosecdef
           AND has_function_privilege('public', procedure_row.oid, 'EXECUTE')
    ),
    'predeploy-disabled migration exposes no M3 RPC through PUBLIC'
);
SELECT is((SELECT count(*) FROM public.passport_aggregates), 0::bigint,
    'fresh predeploy-disabled schema contains no aggregate projection rows');
SELECT is((SELECT count(*) FROM public.visit_records), 0::bigint,
    'fresh predeploy-disabled schema contains no visit history rows');
SELECT ok(
    NOT has_table_privilege('authenticated', 'public.dataset_manifests', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'public.mountains', 'INSERT'),
    'additive M3 migrations do not widen authenticated reference-data import privileges'
);

SELECT * FROM finish();
ROLLBACK;
