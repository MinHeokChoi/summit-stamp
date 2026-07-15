-- M6 release-transition authority. This is an append-only controller ledger;
-- it deliberately has no genesis row, manifest, or alternate writer.
BEGIN;

CREATE SCHEMA IF NOT EXISTS m6_private;
REVOKE ALL ON SCHEMA m6_private FROM PUBLIC;

CREATE TABLE public.release_transition_events (
    release_id text NOT NULL CHECK (
        release_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$'
    ),
    sequence bigint NOT NULL CHECK (sequence > 0),
    state text NOT NULL CHECK (state IN (
        'predeploy-disabled',
        'compatibility',
        'pitr-proof',
        'activate-1pct',
        'phase-5',
        'phase-25',
        'phase-50',
        'phase-100',
        'contract-remove-old'
    )),
    previous_event_sha text NOT NULL CHECK (previous_event_sha ~ '^[0-9a-f]{64}$'),
    event_sha text NOT NULL UNIQUE CHECK (event_sha ~ '^[0-9a-f]{64}$'),
    tag text NOT NULL CHECK (
        tag ~ '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
    ),
    commit_sha text NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    migration_sha text NOT NULL CHECK (migration_sha ~ '^[0-9a-f]{64}$'),
    dataset_sha text NOT NULL CHECK (dataset_sha ~ '^[0-9a-f]{64}$'),
    switch_state text NOT NULL CHECK (switch_state IN ('disabled', 'enabled')),
    approval_sha text NOT NULL UNIQUE CHECK (approval_sha ~ '^[0-9a-f]{64}$'),
    observed_source_sha text NOT NULL UNIQUE CHECK (observed_source_sha ~ '^[0-9a-f]{64}$'),
    actor_id uuid NOT NULL,
    audit_event_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (release_id, sequence)
);

-- The byte sequence fed to SHA-256 is the UTF-8 encoding of the compact,
-- sorted-key JSON emitted by the format string below. The field order is part
-- of the contract; the database never hashes a caller-provided serialization.
CREATE OR REPLACE FUNCTION m6_private.release_transition_sentinel_sha(
    p_release_id text,
    p_tag text,
    p_commit_sha text,
    p_dataset_sha text,
    p_migration_sha text
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, m6_private, extensions
AS $function$
DECLARE
    v_canonical_json text;
BEGIN
    v_canonical_json := format(
        '{"commit":%s,"datasetSHA":%s,"migrationSHA":%s,"releaseID":%s,"schemaVersion":"m6-release-transition-v1","tag":%s}',
        to_json(p_commit_sha)::text,
        to_json(p_dataset_sha)::text,
        to_json(p_migration_sha)::text,
        to_json(p_release_id)::text,
        to_json(p_tag)::text
    );

    RETURN encode(
        extensions.digest(convert_to(v_canonical_json, 'UTF8'), 'sha256'),
        'hex'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m6_private.release_transition_event_sha(
    p_release_id text,
    p_sequence bigint,
    p_state text,
    p_previous_event_sha text,
    p_tag text,
    p_commit_sha text,
    p_migration_sha text,
    p_dataset_sha text,
    p_switch_state text,
    p_approval_sha text,
    p_observed_source_sha text,
    p_actor_id uuid,
    p_audit_event_id uuid
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, m6_private, extensions
AS $function$
DECLARE
    v_canonical_json text;
BEGIN
    v_canonical_json := format(
        '{"schemaVersion":"m6-release-transition-v1","releaseID":%s,"sequence":%s,"state":%s,"previousEventSHA":%s,"tag":%s,"commit":%s,"migrationSHA":%s,"datasetSHA":%s,"switchState":%s,"approvalSHA":%s,"observedSourceSHA":%s,"actorID":%s,"auditEventID":%s}',
        to_json(p_release_id)::text,
        p_sequence,
        to_json(p_state)::text,
        to_json(p_previous_event_sha)::text,
        to_json(p_tag)::text,
        to_json(p_commit_sha)::text,
        to_json(p_migration_sha)::text,
        to_json(p_dataset_sha)::text,
        to_json(p_switch_state)::text,
        to_json(p_approval_sha)::text,
        to_json(p_observed_source_sha)::text,
        to_json(p_actor_id::text)::text,
        to_json(p_audit_event_id::text)::text
    );

    RETURN encode(
        extensions.digest(convert_to(v_canonical_json, 'UTF8'), 'sha256'),
        'hex'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m6_private.reject_release_transition_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'release transition events are append-only';
END;
$function$;

CREATE TRIGGER release_transition_events_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON public.release_transition_events
FOR EACH STATEMENT
EXECUTE FUNCTION m6_private.reject_release_transition_mutation();

-- Exact RPC signature:
-- public.append_release_transition(
--   text, text, text, text, text, text, text, bigint, text, text, text, uuid
-- ) RETURNS TABLE(sequence bigint, event_sha text)
--
-- p_actor_id is intentionally absent. A service-only controller is recorded
-- as the fixed m6_release_controller identity; request claims are never used.
CREATE OR REPLACE FUNCTION public.append_release_transition(
    p_release_id text,
    p_state text,
    p_tag text,
    p_commit_sha text,
    p_migration_sha text,
    p_dataset_sha text,
    p_switch_state text,
    p_expected_sequence bigint,
    p_expected_event_sha text,
    p_approval_sha text,
    p_observed_source_sha text,
    p_audit_event_id uuid
)
RETURNS TABLE (
    sequence bigint,
    event_sha text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m6_private, extensions
AS $function$
DECLARE
    v_actor_id constant uuid := '00000000-0000-0000-0000-000000000006'::uuid;
    v_previous public.release_transition_events%ROWTYPE;
    v_has_previous boolean;
    v_expected_sentinel_sha text;
    v_expected_switch_state text;
    v_event_sha text;
    v_next_sequence bigint;
BEGIN
    IF p_release_id IS NULL
        OR p_release_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$'
        OR p_state IS NULL
        OR p_state NOT IN (
            'predeploy-disabled',
            'compatibility',
            'pitr-proof',
            'activate-1pct',
            'phase-5',
            'phase-25',
            'phase-50',
            'phase-100',
            'contract-remove-old'
        )
        OR p_tag IS NULL
        OR p_tag !~ '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
        OR p_commit_sha IS NULL
        OR p_commit_sha !~ '^[0-9a-f]{40}([0-9a-f]{24})?$'
        OR p_migration_sha IS NULL
        OR p_migration_sha !~ '^[0-9a-f]{64}$'
        OR p_dataset_sha IS NULL
        OR p_dataset_sha !~ '^[0-9a-f]{64}$'
        OR p_switch_state IS NULL
        OR p_switch_state NOT IN ('disabled', 'enabled')
        OR p_expected_sequence IS NULL
        OR p_expected_sequence < 0
        OR p_expected_event_sha IS NULL
        OR p_expected_event_sha !~ '^[0-9a-f]{64}$'
        OR p_approval_sha IS NULL
        OR p_approval_sha !~ '^[0-9a-f]{64}$'
        OR p_observed_source_sha IS NULL
        OR p_observed_source_sha !~ '^[0-9a-f]{64}$'
        OR p_audit_event_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'release transition context rejected';
    END IF;

    v_expected_switch_state := CASE p_state
        WHEN 'predeploy-disabled' THEN 'disabled'
        WHEN 'compatibility' THEN 'disabled'
        WHEN 'pitr-proof' THEN 'disabled'
        ELSE 'enabled'
    END;

    IF p_switch_state IS DISTINCT FROM v_expected_switch_state THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'release transition switch state rejected';
    END IF;

    -- The fixed controller identity remains auditable when auth.uid() is absent
    -- and cannot be selected by an RPC caller.

    -- A collision only serializes unrelated releases; one release always obtains
    -- the same transaction-scoped lock before reading or appending its chain.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('m6-release-transition-v1:' || p_release_id, 0)
    );

    SELECT event_row.*
      INTO v_previous
      FROM public.release_transition_events AS event_row
     WHERE event_row.release_id = p_release_id
     ORDER BY event_row.sequence DESC
     LIMIT 1;
    v_has_previous := FOUND;

    v_expected_sentinel_sha := m6_private.release_transition_sentinel_sha(
        p_release_id,
        p_tag,
        p_commit_sha,
        p_dataset_sha,
        p_migration_sha
    );

    IF NOT v_has_previous THEN
        IF p_expected_sequence <> 0
            OR p_expected_event_sha IS DISTINCT FROM v_expected_sentinel_sha
            OR p_state IS DISTINCT FROM 'predeploy-disabled' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'release transition genesis predecessor rejected';
        END IF;

        v_next_sequence := 1;
    ELSE
        -- The sentinel is a first-transition predecessor only. It cannot be
        -- replayed as a later predecessor, even if a caller changes context.
        IF p_expected_event_sha = v_expected_sentinel_sha THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'release transition sentinel replay rejected';
        END IF;

        IF p_expected_sequence <> v_previous.sequence
            OR p_expected_event_sha IS DISTINCT FROM v_previous.event_sha THEN
            RAISE EXCEPTION USING
                ERRCODE = '40001',
                MESSAGE = 'release transition compare-and-swap rejected';
        END IF;

        IF p_tag IS DISTINCT FROM v_previous.tag
            OR p_commit_sha IS DISTINCT FROM v_previous.commit_sha
            OR p_migration_sha IS DISTINCT FROM v_previous.migration_sha
            OR p_dataset_sha IS DISTINCT FROM v_previous.dataset_sha THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'release transition immutable context rejected';
        END IF;

        IF NOT (
            (v_previous.state = 'predeploy-disabled' AND p_state = 'compatibility')
            OR (v_previous.state = 'compatibility' AND p_state = 'pitr-proof')
            OR (v_previous.state = 'pitr-proof' AND p_state = 'activate-1pct')
            OR (v_previous.state = 'activate-1pct' AND p_state = 'phase-5')
            OR (v_previous.state = 'phase-5' AND p_state = 'phase-25')
            OR (v_previous.state = 'phase-25' AND p_state = 'phase-50')
            OR (v_previous.state = 'phase-50' AND p_state = 'phase-100')
            OR (v_previous.state = 'phase-100' AND p_state = 'contract-remove-old')
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'release transition state rejected';
        END IF;

        v_next_sequence := v_previous.sequence + 1;
    END IF;

    -- A fresh approval and observed source are single-use authority inputs. The
    -- audit identifier is also one-to-one with a durable transition event.
    IF EXISTS (
        SELECT 1
          FROM public.release_transition_events AS event_row
         WHERE event_row.approval_sha = p_approval_sha
            OR event_row.observed_source_sha = p_observed_source_sha
            OR event_row.audit_event_id = p_audit_event_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'release transition immutable evidence rejected';
    END IF;

    v_event_sha := m6_private.release_transition_event_sha(
        p_release_id,
        v_next_sequence,
        p_state,
        p_expected_event_sha,
        p_tag,
        p_commit_sha,
        p_migration_sha,
        p_dataset_sha,
        p_switch_state,
        p_approval_sha,
        p_observed_source_sha,
        v_actor_id,
        p_audit_event_id
    );

    INSERT INTO public.release_transition_events AS event_row (
        release_id,
        sequence,
        state,
        previous_event_sha,
        event_sha,
        tag,
        commit_sha,
        migration_sha,
        dataset_sha,
        switch_state,
        approval_sha,
        observed_source_sha,
        actor_id,
        audit_event_id
    ) VALUES (
        p_release_id,
        v_next_sequence,
        p_state,
        p_expected_event_sha,
        v_event_sha,
        p_tag,
        p_commit_sha,
        p_migration_sha,
        p_dataset_sha,
        p_switch_state,
        p_approval_sha,
        p_observed_source_sha,
        v_actor_id,
        p_audit_event_id
    );

    RETURN QUERY
    SELECT v_next_sequence, v_event_sha;
END;
$function$;

ALTER TABLE public.release_transition_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.release_transition_events FORCE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE public.release_transition_events FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m6_private FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.append_release_transition(
    text, text, text, text, text, text, text, bigint, text, text, text, uuid
) FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA m6_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.release_transition_events FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m6_private FROM %I', role_name);
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON FUNCTION public.append_release_transition(text,text,text,text,text,text,text,bigint,text,text,text,uuid) FROM %I',
                role_name
            );
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        GRANT EXECUTE ON FUNCTION public.append_release_transition(
            text, text, text, text, text, text, text, bigint, text, text, text, uuid
        ) TO service_role;
    END IF;
END;
$block$;

COMMENT ON TABLE public.release_transition_events IS
    'Authoritative M6/M7 append-only release lineage; no genesis event row exists.';
COMMENT ON FUNCTION public.append_release_transition(
    text, text, text, text, text, text, text, bigint, text, text, text, uuid
) IS
    'Service-only CAS append; fixed m6_release_controller identity; exact UTF-8 compact canonical JSON described in migration 0007.';

COMMIT;
