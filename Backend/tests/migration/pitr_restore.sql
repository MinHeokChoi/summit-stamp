-- MIG-005: local source preflight for a future protected PITR restore receipt.
-- It proves the restored M3 schema, grants, RPCs, projections, history, and audit
-- inventory; it neither invokes nor claims a protected or live PITR drill.
BEGIN;

SELECT plan(19);

CREATE OR REPLACE FUNCTION pg_temp.api_roles_cannot_mutate(p_relations text[])
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
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

CREATE OR REPLACE FUNCTION pg_temp.protected_relation_inventory_matches()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('public.profiles', 'r'::"char"),
                ('public.passport_global_state', 'r'::"char"),
                ('public.m3_known_mountains', 'r'::"char"),
                ('public.passport_aggregates', 'r'::"char"),
                ('public.passport_plans', 'r'::"char"),
                ('public.passport_visits', 'r'::"char"),
                ('public.passport_stamps', 'r'::"char"),
                ('public.passport_tombstones', 'r'::"char"),
                ('public.passport_mutation_receipts', 'r'::"char"),
                ('public.passport_snapshots', 'r'::"char"),
                ('public.passport_changes', 'r'::"char"),
                ('m3_private.sync_hmac_keys', 'r'::"char"),
                ('public.m3_history_tokens', 'r'::"char"),
                ('public.m3_history_cursors', 'r'::"char")
          ) AS required_relation(relation_name, relation_kind)
          LEFT JOIN pg_class AS relation_row
            ON relation_row.oid = to_regclass(required_relation.relation_name)
         WHERE relation_row.oid IS NULL
            OR relation_row.relkind <> required_relation.relation_kind
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.protected_rls_contract_matches()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('public.profiles', true, true),
                ('public.passport_global_state', true, true),
                ('public.m3_known_mountains', true, false),
                ('public.passport_aggregates', true, true),
                ('public.passport_plans', true, true),
                ('public.passport_visits', true, true),
                ('public.passport_stamps', true, true),
                ('public.passport_tombstones', true, true),
                ('public.passport_mutation_receipts', true, true),
                ('public.passport_snapshots', true, true),
                ('public.passport_changes', true, true),
                ('m3_private.sync_hmac_keys', true, false),
                ('public.m3_history_tokens', true, true),
                ('public.m3_history_cursors', true, true)
          ) AS required_relation(relation_name, rls_enabled, force_rls)
          LEFT JOIN pg_class AS relation_row
            ON relation_row.oid = to_regclass(required_relation.relation_name)
         WHERE relation_row.oid IS NULL
            OR relation_row.relrowsecurity IS DISTINCT FROM required_relation.rls_enabled
            OR relation_row.relforcerowsecurity IS DISTINCT FROM required_relation.force_rls
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.compatibility_views_match()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('public.mountain_plans', 'public.passport_plans'),
                ('public.visit_records', 'public.passport_visits'),
                ('public.stamps', 'public.passport_stamps'),
                ('public.mutation_receipts', 'public.passport_mutation_receipts'),
                ('public.audit_events', 'public.passport_changes')
          ) AS required_view(view_name, canonical_relation_name)
          LEFT JOIN pg_class AS view_row
            ON view_row.oid = to_regclass(required_view.view_name)
         WHERE view_row.oid IS NULL
            OR view_row.relkind <> 'v'::"char"
            OR (view_row.reloptions @> ARRAY['security_barrier=true']) IS DISTINCT FROM true
            OR NOT EXISTS (
                SELECT 1
                  FROM pg_rewrite AS rewrite_row
                  JOIN pg_depend AS dependency_row
                    ON dependency_row.classid = 'pg_rewrite'::regclass
                   AND dependency_row.objid = rewrite_row.oid
                 WHERE rewrite_row.ev_class = view_row.oid
                   AND dependency_row.refobjid = to_regclass(required_view.canonical_relation_name)
                   AND dependency_row.deptype = 'n'
            )
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.m3_rpcs_match()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                (
                    'public.m3_apply_passport_mutation(text,text,uuid,text,jsonb)',
                    'search_path=pg_catalog, m2a_private, m3_private'
                ),
                (
                    'public.m3_self_bootstrap(text,text)',
                    'search_path=pg_catalog, m2a_private, m3_private, extensions'
                ),
                (
                    'public.m3_self_history_page(text,text,text,integer)',
                    'search_path=pg_catalog, m2a_private, m3_private, extensions'
                ),
                (
                    'public.m3_self_changes(text,text,integer)',
                    'search_path=pg_catalog, m2a_private, m3_private, extensions'
                )
          ) AS required_rpc(signature, expected_search_path)
          LEFT JOIN pg_proc AS procedure_row
            ON procedure_row.oid = to_regprocedure(required_rpc.signature)
         WHERE procedure_row.oid IS NULL
            OR NOT procedure_row.prosecdef
            OR procedure_row.proconfig IS DISTINCT FROM ARRAY[required_rpc.expected_search_path]
            OR has_function_privilege('public', procedure_row.oid, 'EXECUTE')
            OR NOT has_function_privilege('authenticated', procedure_row.oid, 'EXECUTE')
            OR has_function_privilege('anon', procedure_row.oid, 'EXECUTE')
            OR has_function_privilege('service_role', procedure_row.oid, 'EXECUTE')
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.append_only_triggers_match()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                (
                    'm3_private.sync_hmac_keys',
                    'sync_hmac_keys_immutable',
                    27::smallint,
                    'm3_private.reject_sync_hmac_key_mutation()'
                ),
                (
                    'public.passport_visits',
                    'passport_visits_audit_immutable',
                    27::smallint,
                    'm3_private.enforce_passport_visit_audit_update()'
                ),
                (
                    'public.passport_tombstones',
                    'passport_tombstones_append_only',
                    58::smallint,
                    'm3_private.reject_passport_append_only_mutation()'
                ),
                (
                    'public.passport_mutation_receipts',
                    'passport_mutation_receipts_append_only',
                    58::smallint,
                    'm3_private.reject_passport_append_only_mutation()'
                ),
                (
                    'public.passport_changes',
                    'passport_changes_append_only',
                    58::smallint,
                    'm3_private.reject_passport_append_only_mutation()'
                )
          ) AS required_trigger(relation_name, trigger_name, trigger_type, function_signature)
          LEFT JOIN pg_trigger AS trigger_row
            ON trigger_row.tgrelid = to_regclass(required_trigger.relation_name)
           AND trigger_row.tgname = required_trigger.trigger_name
         WHERE trigger_row.oid IS NULL
            OR trigger_row.tgisinternal
            OR trigger_row.tgtype <> required_trigger.trigger_type
            OR trigger_row.tgfoid <> to_regprocedure(required_trigger.function_signature)
    );
$function$;

CREATE OR REPLACE FUNCTION pg_temp.required_constraints_exist()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('public.passport_global_state', 'passport_global_state_pkey', 'p'::"char"),
                ('public.passport_global_state', 'passport_global_state_global_version_check', 'c'::"char"),
                ('public.m3_known_mountains', 'm3_known_mountains_mountain_id_check', 'c'::"char"),
                ('public.m3_known_mountains', 'm3_known_mountains_dataset_sha256_check', 'c'::"char"),
                ('public.m3_known_mountains', 'm3_known_mountains_ordinal_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_mountain_id_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_visit_count_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_aggregate_version_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_global_version_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_plan_state_check', 'c'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_stamp_check', 'c'::"char"),
                ('public.passport_plans', 'passport_plans_mountain_id_check', 'c'::"char"),
                ('public.passport_plans', 'passport_plans_aggregate_version_check', 'c'::"char"),
                ('public.passport_plans', 'passport_plans_global_version_check', 'c'::"char"),
                ('public.passport_plans', 'passport_plans_state_check', 'c'::"char"),
                ('public.passport_visits', 'passport_visits_mountain_id_check', 'c'::"char"),
                ('public.passport_visits', 'passport_visits_created_aggregate_version_check', 'c'::"char"),
                ('public.passport_visits', 'passport_visits_created_global_version_check', 'c'::"char"),
                ('public.passport_visits', 'passport_visits_delete_visibility_check', 'c'::"char"),
                ('public.passport_stamps', 'passport_stamps_mountain_id_check', 'c'::"char"),
                ('public.passport_stamps', 'passport_stamps_aggregate_version_check', 'c'::"char"),
                ('public.passport_stamps', 'passport_stamps_global_version_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_mountain_id_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_entity_id_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_aggregate_version_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_global_version_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_payload_check', 'c'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_retention_check', 'c'::"char"),
                ('public.passport_mutation_receipts', 'passport_mutation_receipts_payload_sha256_check', 'c'::"char"),
                ('public.passport_mutation_receipts', 'passport_mutation_receipts_result_check', 'c'::"char"),
                ('public.passport_mutation_receipts', 'passport_mutation_receipts_retention_check', 'c'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_snapshot_version_check', 'c'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_global_version_check', 'c'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_payload_check', 'c'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_actor_version_key', 'u'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_retention_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_mountain_id_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_aggregate_version_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_global_version_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_payload_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_result_check', 'c'::"char"),
                ('public.passport_changes', 'passport_changes_retention_check', 'c'::"char"),
                ('m3_private.sync_hmac_keys', 'sync_hmac_keys_key_id_check', 'c'::"char"),
                ('m3_private.sync_hmac_keys', 'sync_hmac_keys_key_material_check', 'c'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_api_version_check', 'c'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_dataset_sha256_check', 'c'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_snapshot_version_check', 'c'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_retention_check', 'c'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_compaction_check', 'c'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_mountain_id_check', 'c'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_page_size_check', 'c'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_compaction_check', 'c'::"char")
          ) AS required_constraint(relation_name, constraint_name, constraint_type)
          LEFT JOIN pg_constraint AS constraint_row
            ON constraint_row.conrelid = to_regclass(required_constraint.relation_name)
           AND constraint_row.conname = required_constraint.constraint_name
         WHERE constraint_row.oid IS NULL
            OR constraint_row.contype <> required_constraint.constraint_type
    );
$function$;
CREATE OR REPLACE FUNCTION pg_temp.required_key_constraints_exist()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('public.profiles', 'profiles_pkey', 'p'::"char"),
                ('public.passport_global_state', 'passport_global_state_pkey', 'p'::"char"),
                ('public.m3_known_mountains', 'm3_known_mountains_pkey', 'p'::"char"),
                ('public.m3_known_mountains', 'm3_known_mountains_ordinal_key', 'u'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_pkey', 'p'::"char"),
                ('public.passport_aggregates', 'passport_aggregates_actor_id_fkey', 'f'::"char"),
                ('public.passport_plans', 'passport_plans_pkey', 'p'::"char"),
                ('public.passport_plans', 'passport_plans_actor_id_mountain_id_fkey', 'f'::"char"),
                ('public.passport_visits', 'passport_visits_pkey', 'p'::"char"),
                ('public.passport_visits', 'passport_visits_actor_id_mountain_id_fkey', 'f'::"char"),
                ('public.passport_stamps', 'passport_stamps_pkey', 'p'::"char"),
                ('public.passport_stamps', 'passport_stamps_source_visit_id_fkey', 'f'::"char"),
                ('public.passport_stamps', 'passport_stamps_actor_id_mountain_id_fkey', 'f'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_pkey', 'p'::"char"),
                ('public.passport_tombstones', 'passport_tombstones_actor_id_fkey', 'f'::"char"),
                ('public.passport_mutation_receipts', 'passport_mutation_receipts_pkey', 'p'::"char"),
                ('public.passport_mutation_receipts', 'passport_mutation_receipts_actor_id_fkey', 'f'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_pkey', 'p'::"char"),
                ('public.passport_snapshots', 'passport_snapshots_actor_id_fkey', 'f'::"char"),
                ('public.passport_changes', 'passport_changes_pkey', 'p'::"char"),
                ('public.passport_changes', 'passport_changes_actor_global_version_key', 'u'::"char"),
                ('public.passport_changes', 'passport_changes_actor_id_fkey', 'f'::"char"),
                ('m3_private.sync_hmac_keys', 'sync_hmac_keys_pkey', 'p'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_pkey', 'p'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_actor_id_fkey', 'f'::"char"),
                ('public.m3_history_tokens', 'm3_history_tokens_signing_key_id_fkey', 'f'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_pkey', 'p'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_history_token_id_fkey', 'f'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_actor_id_fkey', 'f'::"char"),
                ('public.m3_history_cursors', 'm3_history_cursors_signing_key_id_fkey', 'f'::"char")
          ) AS required_constraint(relation_name, constraint_name, constraint_type)
          LEFT JOIN pg_constraint AS constraint_row
            ON constraint_row.conrelid = to_regclass(required_constraint.relation_name)
           AND constraint_row.conname = required_constraint.constraint_name
         WHERE constraint_row.oid IS NULL
            OR constraint_row.contype <> required_constraint.constraint_type
    );
$function$;


CREATE OR REPLACE FUNCTION pg_temp.key_token_state_matches()
RETURNS boolean
LANGUAGE sql
STABLE
AS $function$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (
            VALUES
                ('m3_private.sync_hmac_keys', 'key_id'),
                ('m3_private.sync_hmac_keys', 'key_material'),
                ('m3_private.sync_hmac_keys', 'active'),
                ('m3_private.sync_hmac_keys', 'configured_at'),
                ('public.m3_history_tokens', 'token_id'),
                ('public.m3_history_tokens', 'actor_id'),
                ('public.m3_history_tokens', 'signing_key_id'),
                ('public.m3_history_tokens', 'api_version'),
                ('public.m3_history_tokens', 'dataset_sha256'),
                ('public.m3_history_tokens', 'snapshot_version'),
                ('public.m3_history_tokens', 'created_at'),
                ('public.m3_history_tokens', 'expires_at'),
                ('public.m3_history_tokens', 'compacted_at'),
                ('public.m3_history_cursors', 'cursor_id'),
                ('public.m3_history_cursors', 'history_token_id'),
                ('public.m3_history_cursors', 'actor_id'),
                ('public.m3_history_cursors', 'signing_key_id'),
                ('public.m3_history_cursors', 'mountain_id'),
                ('public.m3_history_cursors', 'page_size'),
                ('public.m3_history_cursors', 'last_visited_at'),
                ('public.m3_history_cursors', 'last_visit_id'),
                ('public.m3_history_cursors', 'created_at'),
                ('public.m3_history_cursors', 'expires_at'),
                ('public.m3_history_cursors', 'compacted_at')
          ) AS required_column(relation_name, column_name)
          LEFT JOIN pg_attribute AS attribute_row
            ON attribute_row.attrelid = to_regclass(required_column.relation_name)
           AND attribute_row.attname = required_column.column_name
           AND attribute_row.attnum > 0
           AND NOT attribute_row.attisdropped
         WHERE attribute_row.attrelid IS NULL
    );
$function$;

SELECT ok(to_regnamespace('extensions') IS NOT NULL,
    'a restoration includes the extensions schema required by M3');
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) AS expected_role(role_name)
         WHERE NOT EXISTS (
                SELECT 1
                  FROM pg_roles AS role_row
                 WHERE role_row.rolname = expected_role.role_name
            )
    ),
    'a restoration includes every API role whose restored grants are asserted'
);
SELECT ok(to_regprocedure('public.m2a_begin_apple_auth_checkpoint()') IS NOT NULL,
    'a restoration retains the M2A anonymous begin RPC');
SELECT ok(to_regprocedure('public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)') IS NOT NULL,
    'a restoration retains the M2A authenticated completion RPC');
SELECT ok(has_function_privilege(
    'anon',
    'public.m2a_begin_apple_auth_checkpoint()'::regprocedure,
    'EXECUTE'
), 'a restoration retains the M2A anonymous begin grant');
SELECT ok(has_function_privilege(
    'authenticated',
    'public.m2a_complete_apple_auth_checkpoint(uuid,text,text,text)'::regprocedure,
    'EXECUTE'
), 'a restoration retains the M2A authenticated completion grant');
SELECT ok(
    NOT EXISTS (
        SELECT 1
          FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) AS expected_role(role_name)
         WHERE has_schema_privilege(expected_role.role_name, 'm3_private', 'USAGE')
    ),
    'a restoration preserves API isolation from the M3 private schema'
);
SELECT ok(pg_temp.protected_relation_inventory_matches(),
    'a restoration includes every protected M3 projection, history, audit, key, and token relation');
SELECT ok(pg_temp.protected_rls_contract_matches(),
    'a restoration preserves the exact enabled and forced RLS contract for every protected M3 relation');
SELECT ok(pg_temp.api_roles_cannot_mutate(ARRAY[
    'public.profiles',
    'public.passport_global_state',
    'public.m3_known_mountains',
    'public.passport_aggregates',
    'public.passport_plans',
    'public.passport_visits',
    'public.passport_stamps',
    'public.passport_tombstones',
    'public.passport_mutation_receipts',
    'public.passport_snapshots',
    'public.passport_changes',
    'm3_private.sync_hmac_keys',
    'public.m3_history_tokens',
    'public.m3_history_cursors'
]), 'a restoration preserves direct INSERT, UPDATE, and DELETE denial on every protected M3 relation');
SELECT ok(pg_temp.compatibility_views_match(),
    'a restoration retains each security-barrier M2 compatibility view over its canonical M3 relation');
SELECT ok(pg_temp.api_roles_cannot_mutate(ARRAY[
    'public.mountain_plans',
    'public.visit_records',
    'public.stamps',
    'public.mutation_receipts',
    'public.audit_events'
]), 'a restoration preserves direct DML denial on every M2 compatibility view');
SELECT ok(pg_temp.m3_rpcs_match(),
    'a restoration retains every exact M3 public RPC signature with fixed-path definer grants');
SELECT ok(pg_temp.append_only_triggers_match(),
    'a restoration retains every M3 immutable visit, append-only audit, and key-state trigger');
SELECT ok(pg_temp.required_constraints_exist(),
    'a restoration retains every named M3 projection, retention, snapshot, history, and cursor constraint');
SELECT ok(pg_temp.required_key_constraints_exist(),
    'a restoration retains every required M3 projection, audit, key, history, and cursor primary, unique, and foreign key constraint');
SELECT ok(
    EXISTS (
        SELECT 1
          FROM pg_index AS index_row
          JOIN pg_class AS index_class
            ON index_class.oid = index_row.indexrelid
         WHERE index_row.indrelid = 'm3_private.sync_hmac_keys'::regclass
           AND index_class.relname = 'sync_hmac_keys_one_active_idx'
           AND index_row.indisunique
           AND pg_get_expr(index_row.indpred, index_row.indrelid) = 'active'
    ),
    'a restoration retains the single-active protected sync HMAC key state index'
);
SELECT ok(pg_temp.key_token_state_matches(),
    'a restoration retains every protected sync key, history token, and cursor state column');
SELECT ok(
    to_regclass('public.passport_visits') IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
          FROM unnest(ARRAY[
              'visit_id',
              'created_aggregate_version',
              'created_global_version',
              'deleted_aggregate_version',
              'deleted_global_version',
              'deleted_at'
          ]) AS required_column(column_name)
         WHERE NOT EXISTS (
                SELECT 1
                  FROM pg_attribute AS attribute_row
                 WHERE attribute_row.attrelid = 'public.passport_visits'::regclass
                   AND attribute_row.attname = required_column.column_name
                   AND attribute_row.attnum > 0
                   AND NOT attribute_row.attisdropped
            )
    ),
    'a restoration retains versioned immutable visit history state'
);

SELECT * FROM finish();
ROLLBACK;
