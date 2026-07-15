-- M3 self-read authority is intentionally separate from the mutation path. Every
-- client-visible read is actor-bound, snapshot-bound, and reached only through
-- fixed-search-path SECURITY DEFINER RPCs.
BEGIN;


-- Key material is provisioned only through the protected database configuration
-- path. Tokens retain their signing-key identifier so a retired key can verify
-- already-issued tokens through their 90-day lifetime without becoming active.
CREATE TABLE m3_private.sync_hmac_keys (
    key_id smallint PRIMARY KEY CHECK (key_id > 0),
    key_material bytea NOT NULL CHECK (octet_length(key_material) >= 32),
    active boolean NOT NULL DEFAULT true,
    configured_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX sync_hmac_keys_one_active_idx
    ON m3_private.sync_hmac_keys (active)
    WHERE active;

-- The raw token is never stored. A random identifier plus an HMAC is opaque to
-- the client; all actor, API, dataset, and snapshot bindings remain server-side.
CREATE TABLE public.m3_history_tokens (
    token_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    signing_key_id smallint NOT NULL REFERENCES m3_private.sync_hmac_keys (key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    api_version text NOT NULL CHECK (
        api_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
    ),
    dataset_sha256 text NOT NULL CHECK (dataset_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot_version bigint NOT NULL CHECK (snapshot_version >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    compacted_at timestamptz,
    CONSTRAINT m3_history_tokens_retention_check CHECK (
        expires_at >= created_at + interval '90 days'
    ),
    CONSTRAINT m3_history_tokens_compaction_check CHECK (
        compacted_at IS NULL OR compacted_at >= created_at
    )
);

CREATE INDEX m3_history_tokens_actor_expiry_idx
    ON public.m3_history_tokens (actor_id, expires_at);

-- A cursor persists the complete request binding rather than serializing it into
-- an inspectable client token. It must point at the exact bootstrap token that
-- established its snapshot.
CREATE TABLE public.m3_history_cursors (
    cursor_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    history_token_id uuid NOT NULL REFERENCES public.m3_history_tokens (token_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    signing_key_id smallint NOT NULL REFERENCES m3_private.sync_hmac_keys (key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    mountain_id text NOT NULL CHECK (
        btrim(mountain_id) <> '' AND octet_length(mountain_id) <= 512
    ),
    page_size integer NOT NULL CHECK (page_size BETWEEN 1 AND 100),
    last_visited_at timestamptz NOT NULL,
    last_visit_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    compacted_at timestamptz,
    CONSTRAINT m3_history_cursors_compaction_check CHECK (
        compacted_at IS NULL OR compacted_at >= created_at
    )
);

CREATE INDEX m3_history_cursors_token_expiry_idx
    ON public.m3_history_cursors (history_token_id, expires_at);
-- Change cursors bind every mutable paging value to the bootstrap history
-- capability that established the accepted baseline.
CREATE TABLE public.m3_change_cursors (
    cursor_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    history_token_id uuid NOT NULL REFERENCES public.m3_history_tokens (token_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    signing_key_id smallint NOT NULL REFERENCES m3_private.sync_hmac_keys (key_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    api_version text NOT NULL CHECK (
        api_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
    ),
    dataset_sha256 text NOT NULL CHECK (dataset_sha256 ~ '^[0-9a-f]{64}$'),
    baseline_version bigint NOT NULL CHECK (baseline_version >= 0),
    through_version bigint NOT NULL CHECK (through_version >= baseline_version),
    page_size integer NOT NULL CHECK (page_size BETWEEN 1 AND 500),
    next_version bigint NOT NULL CHECK (
        next_version >= baseline_version AND next_version < through_version
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    compacted_at timestamptz,
    CONSTRAINT m3_change_cursors_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT m3_change_cursors_compaction_check CHECK (
        compacted_at IS NULL OR compacted_at >= created_at
    )
);

CREATE INDEX m3_change_cursors_token_expiry_idx
    ON public.m3_change_cursors (history_token_id, expires_at);

CREATE OR REPLACE FUNCTION m3_private.reject_sync_hmac_key_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'sync HMAC keys cannot be deleted';
    END IF;

    IF NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.key_material IS DISTINCT FROM OLD.key_material
        OR NEW.configured_at IS DISTINCT FROM OLD.configured_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'sync HMAC key material is immutable';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER sync_hmac_keys_immutable
    BEFORE UPDATE OR DELETE ON m3_private.sync_hmac_keys
    FOR EACH ROW
    EXECUTE FUNCTION m3_private.reject_sync_hmac_key_mutation();

CREATE OR REPLACE FUNCTION m3_private.require_sync_api_version(p_api_version text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_api_version IS DISTINCT FROM 'm3-v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync API version rejected';
    END IF;

    RETURN p_api_version;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_sync_dataset_sha256(p_dataset_sha256 text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_dataset_sha256 IS NULL
        OR p_dataset_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync dataset binding rejected';
    END IF;

    RETURN p_dataset_sha256;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_sync_page_size(p_page_size integer)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_page_size IS NULL OR p_page_size NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync page size rejected';
    END IF;

    RETURN p_page_size;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.assert_current_known_dataset(
    p_dataset_sha256 text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_mountain_count bigint;
    v_ordinal_count bigint;
    v_dataset_count bigint;
    v_first_ordinal smallint;
    v_last_ordinal smallint;
    v_dataset_sha256 text;
BEGIN
    SELECT count(*),
           count(DISTINCT known.ordinal),
           count(DISTINCT known.dataset_sha256),
           min(known.ordinal),
           max(known.ordinal),
           min(known.dataset_sha256)
      INTO v_mountain_count,
           v_ordinal_count,
           v_dataset_count,
           v_first_ordinal,
           v_last_ordinal,
           v_dataset_sha256
      FROM public.m3_known_mountains AS known;

    IF v_mountain_count <> 100
        OR v_ordinal_count <> 100
        OR v_dataset_count <> 1
        OR v_first_ordinal <> 1
        OR v_last_ordinal <> 100
        OR v_dataset_sha256 IS DISTINCT FROM p_dataset_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport sync known mountain set is unavailable';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_known_mountain(
    p_mountain_id text,
    p_dataset_sha256 text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    PERFORM m3_private.require_mountain_id(p_mountain_id);

    IF NOT EXISTS (
        SELECT 1
          FROM public.m3_known_mountains AS known
         WHERE known.mountain_id = p_mountain_id
           AND known.dataset_sha256 = p_dataset_sha256
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync mountain binding rejected';
    END IF;

    RETURN p_mountain_id;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.active_sync_hmac_key()
RETURNS m3_private.sync_hmac_keys
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_key m3_private.sync_hmac_keys%ROWTYPE;
BEGIN
    SELECT *
      INTO v_key
      FROM m3_private.sync_hmac_keys AS key_row
     WHERE key_row.active
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport sync token signing is unavailable';
    END IF;

    RETURN v_key;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.issue_sync_token(
    p_prefix text,
    p_key_id smallint,
    p_token_id uuid,
    p_key_material bytea
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private, extensions
AS $function$
DECLARE
    v_unsigned text;
    v_signature text;
BEGIN
    IF p_prefix NOT IN ('m3h1', 'm3c1', 'm3d1')
        OR p_key_id IS NULL
        OR p_token_id IS NULL
        OR p_key_material IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync token rejected';
    END IF;

    v_unsigned := concat_ws('.', p_prefix, p_key_id::text, p_token_id::text);
    v_signature := encode(
        extensions.hmac(convert_to(v_unsigned, 'UTF8'), p_key_material, 'sha256'),
        'hex'
    );

    RETURN concat_ws('.', v_unsigned, v_signature);
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.verify_sync_token(
    p_token text,
    p_expected_prefix text
)
RETURNS TABLE (token_id uuid, signing_key_id smallint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private, extensions
AS $function$
DECLARE
    v_prefix text;
    v_key_id_text text;
    v_token_id_text text;
    v_signature text;
    v_unsigned text;
    v_expected_signature text;
    v_key_id smallint;
    v_token_id uuid;
    v_key_material bytea;
BEGIN
    IF p_expected_prefix NOT IN ('m3h1', 'm3c1', 'm3d1')
        OR p_token IS NULL
        OR octet_length(p_token) > 256
        OR p_token !~ '^m3[hcd]1\.[1-9][0-9]{0,4}\.[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync token rejected';
    END IF;

    v_prefix := split_part(p_token, '.', 1);
    v_key_id_text := split_part(p_token, '.', 2);
    v_token_id_text := split_part(p_token, '.', 3);
    v_signature := split_part(p_token, '.', 4);

    IF v_prefix IS DISTINCT FROM p_expected_prefix
        OR split_part(p_token, '.', 5) <> '' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync token rejected';
    END IF;

    BEGIN
        v_key_id := v_key_id_text::smallint;
        v_token_id := v_token_id_text::uuid;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync token rejected';
    END;

    SELECT key_row.key_material
      INTO v_key_material
      FROM m3_private.sync_hmac_keys AS key_row
     WHERE key_row.key_id = v_key_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync token rejected';
    END IF;

    v_unsigned := concat_ws('.', v_prefix, v_key_id::text, v_token_id::text);
    v_expected_signature := encode(
        extensions.hmac(convert_to(v_unsigned, 'UTF8'), v_key_material, 'sha256'),
        'hex'
    );

    IF v_signature IS DISTINCT FROM v_expected_signature THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync token rejected';
    END IF;

    token_id := v_token_id;
    signing_key_id := v_key_id;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_history_token(
    p_history_token text,
    p_actor_id uuid
)
RETURNS public.m3_history_tokens
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_token_id uuid;
    v_key_id smallint;
    v_history_token public.m3_history_tokens%ROWTYPE;
    v_current_global_version bigint;
BEGIN
    SELECT verified.token_id, verified.signing_key_id
      INTO v_token_id, v_key_id
      FROM m3_private.verify_sync_token(p_history_token, 'm3h1') AS verified;

    SELECT *
      INTO v_history_token
      FROM public.m3_history_tokens AS history_token
     WHERE history_token.token_id = v_token_id
       AND history_token.signing_key_id = v_key_id
     FOR KEY SHARE;

    IF NOT FOUND
        OR v_history_token.actor_id IS DISTINCT FROM p_actor_id
        OR v_history_token.expires_at <= clock_timestamp()
        OR v_history_token.compacted_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync history request rejected';
    END IF;

    SELECT state.global_version
      INTO v_current_global_version
      FROM public.passport_global_state AS state
     WHERE state.actor_id = v_history_token.actor_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport sync global state is unavailable';
    END IF;

    IF v_history_token.snapshot_version > v_current_global_version THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync history request rejected';
    END IF;

    RETURN v_history_token;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_history_cursor(
    p_cursor text,
    p_history_token_id uuid,
    p_actor_id uuid,
    p_mountain_id text,
    p_page_size integer
)
RETURNS public.m3_history_cursors
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_cursor_id uuid;
    v_key_id smallint;
    v_cursor public.m3_history_cursors%ROWTYPE;
BEGIN
    SELECT verified.token_id, verified.signing_key_id
      INTO v_cursor_id, v_key_id
      FROM m3_private.verify_sync_token(p_cursor, 'm3c1') AS verified;

    SELECT *
      INTO v_cursor
      FROM public.m3_history_cursors AS cursor_row
     WHERE cursor_row.cursor_id = v_cursor_id
       AND cursor_row.signing_key_id = v_key_id
     FOR KEY SHARE;

    IF NOT FOUND
        OR v_cursor.history_token_id IS DISTINCT FROM p_history_token_id
        OR v_cursor.actor_id IS DISTINCT FROM p_actor_id
        OR v_cursor.mountain_id IS DISTINCT FROM p_mountain_id
        OR v_cursor.page_size IS DISTINCT FROM p_page_size
        OR v_cursor.expires_at <= clock_timestamp()
        OR v_cursor.compacted_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync history request rejected';
    END IF;

    RETURN v_cursor;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_change_limit(p_limit integer)
RETURNS integer
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport sync change limit rejected';
    END IF;

    RETURN p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_change_cursor(
    p_cursor text,
    p_history_token_id uuid,
    p_actor_id uuid,
    p_api_version text,
    p_dataset_sha256 text,
    p_baseline_version bigint,
    p_page_size integer
)
RETURNS public.m3_change_cursors
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_cursor_id uuid;
    v_key_id smallint;
    v_cursor public.m3_change_cursors%ROWTYPE;
BEGIN
    SELECT verified.token_id, verified.signing_key_id
      INTO v_cursor_id, v_key_id
      FROM m3_private.verify_sync_token(p_cursor, 'm3d1') AS verified;

    SELECT *
      INTO v_cursor
      FROM public.m3_change_cursors AS cursor_row
     WHERE cursor_row.cursor_id = v_cursor_id
       AND cursor_row.signing_key_id = v_key_id
     FOR KEY SHARE;

    IF NOT FOUND
        OR v_cursor.history_token_id IS DISTINCT FROM p_history_token_id
        OR v_cursor.actor_id IS DISTINCT FROM p_actor_id
        OR v_cursor.api_version IS DISTINCT FROM p_api_version
        OR v_cursor.dataset_sha256 IS DISTINCT FROM p_dataset_sha256
        OR v_cursor.baseline_version IS DISTINCT FROM p_baseline_version
        OR v_cursor.page_size IS DISTINCT FROM p_page_size
        OR v_cursor.expires_at <= clock_timestamp()
        OR v_cursor.compacted_at IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport sync change request rejected';
    END IF;

    RETURN v_cursor;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.change_window_requires_resync(
    p_actor_id uuid,
    p_baseline_version bigint,
    p_through_version bigint,
    p_now timestamptz
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
    SELECT EXISTS (
        SELECT 1
          FROM public.passport_changes AS change_row
         WHERE change_row.actor_id = p_actor_id
           AND change_row.global_version > p_baseline_version
           AND change_row.global_version <= p_through_version
           AND (
                change_row.created_at < p_now - interval '90 days'
                OR change_row.expires_at <= p_now
           )
    );
$function$;
CREATE OR REPLACE FUNCTION public.m3_self_bootstrap(
    p_api_version text,
    p_dataset_sha256 text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_api_version text;
    v_dataset_sha256 text;
    v_actor_id uuid;
    v_snapshot_version bigint;
    v_now timestamptz;
    v_expires_at timestamptz;
    v_mountains jsonb;
    v_aggregates jsonb;
    v_plans jsonb;
    v_stamps jsonb;
    v_snapshot_payload jsonb;
    v_history_token_id uuid := extensions.gen_random_uuid();
    v_key m3_private.sync_hmac_keys%ROWTYPE;
    v_history_token text;
BEGIN
    v_api_version := m3_private.require_sync_api_version(p_api_version);
    v_dataset_sha256 := m3_private.require_sync_dataset_sha256(p_dataset_sha256);
    v_actor_id := m3_private.current_passport_actor();
    PERFORM m3_private.lock_passport_actor_root(v_actor_id);
    LOCK TABLE public.m3_known_mountains IN SHARE MODE;

    PERFORM m3_private.assert_current_known_dataset(v_dataset_sha256);

    -- This row lock establishes one global read point. A concurrent mutation
    -- cannot publish its new global version until this response is assembled.
    SELECT state.global_version
      INTO v_snapshot_version
      FROM public.passport_global_state AS state
     WHERE state.actor_id = v_actor_id
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport sync global state is unavailable';
    END IF;

    v_now := clock_timestamp();
    v_expires_at := v_now + interval '90 days';


    SELECT coalesce(jsonb_agg(known.mountain_id ORDER BY known.ordinal), '[]'::jsonb),
           coalesce(
               jsonb_agg(
                   jsonb_build_object(
                       'mountainID', known.mountain_id,
                       'visitCount', coalesce(aggregate_row.visit_count, 0),
                       'planState', aggregate_row.plan_state,
                       'aggregateVersion', coalesce(aggregate_row.aggregate_version, 0),
                       'globalVersion', coalesce(aggregate_row.global_version, 0)
                   )
                   ORDER BY known.ordinal
               ),
               '[]'::jsonb
           )
      INTO v_mountains, v_aggregates
      FROM public.m3_known_mountains AS known
      LEFT JOIN public.passport_aggregates AS aggregate_row
        ON aggregate_row.actor_id = v_actor_id
       AND aggregate_row.mountain_id = known.mountain_id
     WHERE known.dataset_sha256 = v_dataset_sha256;

    SELECT coalesce(
               jsonb_agg(
                   jsonb_build_object(
                       'mountainID', plan_row.mountain_id,
                       'planState', plan_row.plan_state,
                       'firstVisitID', plan_row.first_visit_id,
                       'aggregateVersion', plan_row.aggregate_version,
                       'globalVersion', plan_row.global_version,
                       'createdAt', plan_row.created_at,
                       'updatedAt', plan_row.updated_at
                   )
                   ORDER BY known.ordinal
               ),
               '[]'::jsonb
           )
      INTO v_plans
      FROM public.passport_plans AS plan_row
      JOIN public.m3_known_mountains AS known
        ON known.mountain_id = plan_row.mountain_id
       AND known.dataset_sha256 = v_dataset_sha256
     WHERE plan_row.actor_id = v_actor_id;

    SELECT coalesce(
               jsonb_agg(
                   jsonb_build_object(
                       'mountainID', stamp_row.mountain_id,
                       'sourceVisitID', stamp_row.source_visit_id,
                       'earnedAt', stamp_row.earned_at,
                       'verificationMethod', stamp_row.verification_method,
                       'aggregateVersion', stamp_row.aggregate_version,
                       'globalVersion', stamp_row.global_version,
                       'updatedAt', stamp_row.updated_at
                   )
                   ORDER BY known.ordinal
               ),
               '[]'::jsonb
           )
      INTO v_stamps
      FROM public.passport_stamps AS stamp_row
      JOIN public.m3_known_mountains AS known
        ON known.mountain_id = stamp_row.mountain_id
       AND known.dataset_sha256 = v_dataset_sha256
     WHERE stamp_row.actor_id = v_actor_id;

    v_snapshot_payload := jsonb_build_object(
        'snapshotVersion', v_snapshot_version,
        'datasetSHA256', v_dataset_sha256,
        'mountains', v_mountains,
        'aggregates', v_aggregates,
        'plans', v_plans,
        'stamps', v_stamps
    );

    IF v_snapshot_version > 0 THEN
        INSERT INTO public.passport_snapshots (
            actor_id,
            snapshot_version,
            global_version,
            payload,
            created_at,
            expires_at
        ) VALUES (
            v_actor_id,
            v_snapshot_version,
            v_snapshot_version,
            v_snapshot_payload,
            v_now,
            v_expires_at
        )
        ON CONFLICT (actor_id, snapshot_version) DO NOTHING;
    END IF;

    v_key := m3_private.active_sync_hmac_key();
    INSERT INTO public.m3_history_tokens (
        token_id,
        actor_id,
        signing_key_id,
        api_version,
        dataset_sha256,
        snapshot_version,
        created_at,
        expires_at
    ) VALUES (
        v_history_token_id,
        v_actor_id,
        v_key.key_id,
        v_api_version,
        v_dataset_sha256,
        v_snapshot_version,
        v_now,
        v_expires_at
    );

    v_history_token := m3_private.issue_sync_token(
        'm3h1',
        v_key.key_id,
        v_history_token_id,
        v_key.key_material
    );

    RETURN v_snapshot_payload || jsonb_build_object('historyToken', v_history_token);
END;
$function$;

CREATE OR REPLACE FUNCTION public.m3_self_history_page(
    p_history_token text,
    p_cursor text DEFAULT NULL,
    p_mountain_id text DEFAULT NULL,
    p_page_size integer DEFAULT 100
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_history_token public.m3_history_tokens%ROWTYPE;
    v_cursor public.m3_history_cursors%ROWTYPE;
    v_mountain_id text;
    v_page_size integer;
    v_has_cursor boolean := p_cursor IS NOT NULL;
    v_item_count bigint;
    v_items jsonb;
    v_last_visited_at timestamptz;
    v_last_visit_id uuid;
    v_cursor_id uuid;
    v_key m3_private.sync_hmac_keys%ROWTYPE;
    v_next_cursor text;
    v_now timestamptz := clock_timestamp();
BEGIN
    v_actor_id := m3_private.current_passport_actor();
    v_history_token := m3_private.require_history_token(p_history_token, v_actor_id);
    v_page_size := m3_private.require_sync_page_size(p_page_size);
    v_mountain_id := m3_private.require_known_mountain(
        p_mountain_id,
        v_history_token.dataset_sha256
    );

    IF v_has_cursor THEN
        v_cursor := m3_private.require_history_cursor(
            p_cursor,
            v_history_token.token_id,
            v_actor_id,
            v_mountain_id,
            v_page_size
        );
    END IF;

    WITH candidates AS (
        SELECT visit_row.visit_id,
               visit_row.mountain_id,
               visit_row.visited_at,
               visit_row.recorded_at,
               visit_row.verification_method,
               visit_row.created_aggregate_version,
               visit_row.created_global_version
          FROM public.passport_visits AS visit_row
         WHERE visit_row.actor_id = v_actor_id
           AND visit_row.mountain_id = v_mountain_id
           AND visit_row.created_global_version <= v_history_token.snapshot_version
           AND (
                visit_row.deleted_global_version IS NULL
                OR visit_row.deleted_global_version > v_history_token.snapshot_version
           )
           AND (
                NOT v_has_cursor
                OR visit_row.visited_at < v_cursor.last_visited_at
                OR (
                    visit_row.visited_at = v_cursor.last_visited_at
                    AND visit_row.visit_id < v_cursor.last_visit_id
                )
           )
         ORDER BY visit_row.visited_at DESC, visit_row.visit_id DESC
         LIMIT v_page_size + 1
    ), numbered AS (
        SELECT candidates.*, row_number() OVER (
            ORDER BY candidates.visited_at DESC, candidates.visit_id DESC
        ) AS sequence
          FROM candidates
    )
    SELECT count(*),
           coalesce(
               jsonb_agg(
                   jsonb_build_object(
                       'visitID', numbered.visit_id,
                       'mountainID', numbered.mountain_id,
                       'visitedAt', numbered.visited_at,
                       'recordedAt', numbered.recorded_at,
                       'verificationMethod', numbered.verification_method,
                       'createdAggregateVersion', numbered.created_aggregate_version,
                       'createdGlobalVersion', numbered.created_global_version
                   )
                   ORDER BY numbered.sequence
               ) FILTER (WHERE numbered.sequence <= v_page_size),
               '[]'::jsonb
           ),
           (array_agg(numbered.visited_at ORDER BY numbered.sequence)
                FILTER (WHERE numbered.sequence <= v_page_size))[v_page_size],
           (array_agg(numbered.visit_id ORDER BY numbered.sequence)
                FILTER (WHERE numbered.sequence <= v_page_size))[v_page_size]
      INTO v_item_count, v_items, v_last_visited_at, v_last_visit_id
      FROM numbered;

    IF v_item_count > v_page_size THEN
        v_key := m3_private.active_sync_hmac_key();
        v_cursor_id := extensions.gen_random_uuid();

        INSERT INTO public.m3_history_cursors (
            cursor_id,
            history_token_id,
            actor_id,
            signing_key_id,
            mountain_id,
            page_size,
            last_visited_at,
            last_visit_id,
            created_at,
            expires_at
        ) VALUES (
            v_cursor_id,
            v_history_token.token_id,
            v_actor_id,
            v_key.key_id,
            v_mountain_id,
            v_page_size,
            v_last_visited_at,
            v_last_visit_id,
            v_now,
            v_history_token.expires_at
        );

        v_next_cursor := m3_private.issue_sync_token(
            'm3c1',
            v_key.key_id,
            v_cursor_id,
            v_key.key_material
        );
    END IF;

    RETURN jsonb_build_object(
        'snapshotVersion', v_history_token.snapshot_version,
        'items', v_items,
        'nextCursor', v_next_cursor,
        'complete', v_item_count <= v_page_size
    );
END;
$function$;

DROP FUNCTION IF EXISTS public.m3_self_changes(bigint, integer);

CREATE OR REPLACE FUNCTION public.m3_self_changes(
    p_history_token text,
    p_cursor text DEFAULT NULL,
    p_limit integer DEFAULT 500
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_history_token public.m3_history_tokens%ROWTYPE;
    v_cursor public.m3_change_cursors%ROWTYPE;
    v_baseline_version bigint;
    v_from_version bigint;
    v_through_version bigint;
    v_limit integer;
    v_has_cursor boolean := p_cursor IS NOT NULL;
    v_now timestamptz := clock_timestamp();
    v_item_count bigint;
    v_changes jsonb;
    v_next_version bigint;
    v_cursor_id uuid;
    v_key m3_private.sync_hmac_keys%ROWTYPE;
    v_next_cursor text;
BEGIN
    v_actor_id := m3_private.current_passport_actor();
    v_history_token := m3_private.require_history_token(p_history_token, v_actor_id);
    v_limit := m3_private.require_change_limit(p_limit);

    IF v_has_cursor THEN
        v_cursor := m3_private.require_change_cursor(
            p_cursor,
            v_history_token.token_id,
            v_actor_id,
            v_history_token.api_version,
            v_history_token.dataset_sha256,
            v_history_token.snapshot_version,
            v_limit
        );
        v_baseline_version := v_cursor.baseline_version;
        v_from_version := v_cursor.next_version;
        v_through_version := v_cursor.through_version;
    ELSE
        v_baseline_version := v_history_token.snapshot_version;
        v_from_version := v_baseline_version;

        -- Only the first page chooses a target. Every continuation reads the
        -- target persisted in its opaque change cursor.
        SELECT state.global_version
          INTO v_through_version
          FROM public.passport_global_state AS state
         WHERE state.actor_id = v_actor_id
         FOR SHARE;

        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'passport sync global state is unavailable';
        END IF;
    END IF;

    -- The complete bootstrap-to-target window must remain available. A retained
    -- suffix is never returned after any expired fact in that window.
    IF m3_private.change_window_requires_resync(
        v_actor_id,
        v_baseline_version,
        v_through_version,
        v_now
    ) THEN
        IF v_has_cursor THEN
            UPDATE public.m3_change_cursors
               SET compacted_at = v_now
             WHERE cursor_id = v_cursor.cursor_id
               AND compacted_at IS NULL;
        END IF;

        RAISE EXCEPTION USING
            ERRCODE = 'PT410',
            MESSAGE = 'passport sync history expired';
    END IF;

    WITH candidates AS (
        SELECT change_row.global_version,
               change_row.mountain_id,
               change_row.operation,
               change_row.aggregate_version,
               change_row.result
          FROM public.passport_changes AS change_row
         WHERE change_row.actor_id = v_actor_id
           AND change_row.global_version > v_from_version
           AND change_row.global_version <= v_through_version
         ORDER BY change_row.global_version
         LIMIT v_limit + 1
    ), numbered AS (
        SELECT candidates.*, row_number() OVER (ORDER BY candidates.global_version) AS sequence
          FROM candidates
    )
    SELECT count(*),
           coalesce(
               jsonb_agg(
                   jsonb_build_object(
                       'globalVersion', numbered.global_version,
                       'mountainID', numbered.mountain_id,
                       'operation', numbered.operation,
                       'aggregateVersion', numbered.aggregate_version,
                       'result', numbered.result
                   )
                   ORDER BY numbered.sequence
               ) FILTER (WHERE numbered.sequence <= v_limit),
               '[]'::jsonb
           ),
           (array_agg(numbered.global_version ORDER BY numbered.sequence)
                FILTER (WHERE numbered.sequence <= v_limit))[v_limit]
      INTO v_item_count, v_changes, v_next_version
      FROM numbered;

    IF v_item_count <= v_limit THEN
        v_next_version := v_through_version;
    ELSE
        v_key := m3_private.active_sync_hmac_key();
        v_cursor_id := extensions.gen_random_uuid();

        INSERT INTO public.m3_change_cursors (
            cursor_id,
            history_token_id,
            actor_id,
            signing_key_id,
            api_version,
            dataset_sha256,
            baseline_version,
            through_version,
            page_size,
            next_version,
            created_at,
            expires_at
        ) VALUES (
            v_cursor_id,
            v_history_token.token_id,
            v_actor_id,
            v_key.key_id,
            v_history_token.api_version,
            v_history_token.dataset_sha256,
            v_baseline_version,
            v_through_version,
            v_limit,
            v_next_version,
            v_now,
            v_history_token.expires_at
        );

        v_next_cursor := m3_private.issue_sync_token(
            'm3d1',
            v_key.key_id,
            v_cursor_id,
            v_key.key_material
        );
    END IF;

    RETURN jsonb_build_object(
        'fromVersion', v_from_version,
        'throughVersion', v_through_version,
        'changes', v_changes,
        'nextVersion', v_next_version,
        'nextCursor', v_next_cursor,
        'complete', v_item_count <= v_limit,
        'resyncRequired', false
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m3_apply_passport_mutation(
    p_api_version text,
    p_dataset_sha256 text,
    p_mutation_id uuid,
    p_operation text,
    p_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private
AS $function$
DECLARE
    v_keys text[];
    v_mountain_id text;
    v_visit_id uuid;
    v_visited_at timestamptz;
    v_result jsonb;
    v_bootstrap jsonb;
    v_dataset_sha256 text;
BEGIN
    IF p_api_version IS DISTINCT FROM 'm3-v1'
        OR p_payload IS NULL
        OR jsonb_typeof(p_payload) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport mutation compatibility rejected';
    END IF;

    v_dataset_sha256 := m3_private.require_sync_dataset_sha256(p_dataset_sha256);
    PERFORM m3_private.assert_current_known_dataset(v_dataset_sha256);
    PERFORM m3_private.require_mutation_id(p_mutation_id);

    SELECT array_agg(key ORDER BY key)
      INTO v_keys
      FROM jsonb_object_keys(p_payload) AS key;

    CASE p_operation
        WHEN 'plan_add' THEN
            IF v_keys IS DISTINCT FROM ARRAY['mountainID']::text[] THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END IF;
            v_mountain_id := m3_private.require_known_mountain(
                p_payload ->> 'mountainID', v_dataset_sha256
            );
            v_result := public.passport_add_plan(v_mountain_id, p_mutation_id);
        WHEN 'plan_remove' THEN
            IF v_keys IS DISTINCT FROM ARRAY['mountainID']::text[] THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END IF;
            v_mountain_id := m3_private.require_known_mountain(
                p_payload ->> 'mountainID', v_dataset_sha256
            );
            v_result := public.passport_remove_plan(v_mountain_id, p_mutation_id);
        WHEN 'manual_visit_create' THEN
            IF v_keys IS DISTINCT FROM ARRAY['mountainID', 'visitID', 'visitedAt']::text[] THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END IF;
            v_mountain_id := m3_private.require_known_mountain(
                p_payload ->> 'mountainID', v_dataset_sha256
            );
            BEGIN
                v_visit_id := (p_payload ->> 'visitID')::uuid;
                v_visited_at := (p_payload ->> 'visitedAt')::timestamptz;
            EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END;
            v_result := public.passport_create_manual_visit(
                v_mountain_id, v_visit_id, v_visited_at, p_mutation_id
            );
        WHEN 'manual_visit_delete' THEN
            IF v_keys IS DISTINCT FROM ARRAY['visitID']::text[] THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END IF;
            BEGIN
                v_visit_id := (p_payload ->> 'visitID')::uuid;
            EXCEPTION WHEN invalid_text_representation THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'passport mutation payload rejected';
            END;
            v_result := public.passport_delete_manual_visit(v_visit_id, p_mutation_id);
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'passport mutation operation rejected';
    END CASE;

    v_bootstrap := public.m3_self_bootstrap(p_api_version, v_dataset_sha256);
    RETURN v_result || jsonb_build_object(
        'history_token', v_bootstrap ->> 'historyToken'
    );
END;
$function$;
REVOKE ALL PRIVILEGES ON FUNCTION public.m3_apply_passport_mutation(text, text, uuid, text, jsonb) FROM PUBLIC;

ALTER TABLE public.m3_known_mountains ENABLE ROW LEVEL SECURITY;
ALTER TABLE m3_private.sync_hmac_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m3_history_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m3_history_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE public.m3_history_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m3_history_cursors FORCE ROW LEVEL SECURITY;
ALTER TABLE public.m3_change_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m3_change_cursors FORCE ROW LEVEL SECURITY;

CREATE POLICY m3_history_tokens_actor_boundary ON public.m3_history_tokens
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY m3_history_cursors_actor_boundary ON public.m3_history_cursors
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY m3_change_cursors_actor_boundary ON public.m3_change_cursors
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());

REVOKE ALL PRIVILEGES ON SCHEMA m3_private FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m3_known_mountains FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE m3_private.sync_hmac_keys FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m3_history_tokens FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m3_history_cursors FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m3_change_cursors FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m3_private FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_bootstrap(text, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_history_page(text, text, text, integer) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_changes(text, text, integer) FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA m3_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m3_known_mountains FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE m3_private.sync_hmac_keys FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m3_history_tokens FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m3_history_cursors FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m3_change_cursors FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m3_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_bootstrap(text, text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_history_page(text, text, text, integer) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m3_self_changes(text, text, integer) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m3_apply_passport_mutation(text, text, uuid, text, jsonb) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_add_plan(text, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_remove_plan(text, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) FROM %I', role_name);
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT EXECUTE ON FUNCTION public.m3_self_bootstrap(text, text) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m3_self_history_page(text, text, text, integer) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m3_self_changes(text, text, integer) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m3_apply_passport_mutation(text, text, uuid, text, jsonb) TO authenticated;
    END IF;
END;
$block$;

COMMENT ON TABLE public.m3_known_mountains IS
    'Protected authoritative current set of exactly 100 opaque MountainIDs for M3 self bootstrap.';
COMMENT ON TABLE m3_private.sync_hmac_keys IS
    'Protected HMAC key material for opaque M3 history and change cursor tokens; never API-readable.';
COMMENT ON TABLE public.m3_history_tokens IS
    'Actor-, API-, dataset-, and snapshot-bound opaque history token state retained for 90 days.';
COMMENT ON TABLE public.m3_history_cursors IS
    'Actor-bound opaque history continuation state; cursors cannot be mixed across request bindings.';
COMMENT ON TABLE public.m3_change_cursors IS
    'Actor-, API-, dataset-, baseline-, and target-bound opaque M3 change continuations.';

COMMIT;
