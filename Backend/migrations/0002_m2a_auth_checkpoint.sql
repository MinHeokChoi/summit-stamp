-- M2A is an auth-only checkpoint. It stores challenge commitments and redacted
-- correlation receipts only; no Apple profile fields or OAuth callback material belong here.
BEGIN;

CREATE SCHEMA IF NOT EXISTS m2a_private;
REVOKE ALL ON SCHEMA m2a_private FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.m2a_auth_checkpoint_policy (
    singleton smallint PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    expected_issuer_sha256 text NOT NULL CHECK (expected_issuer_sha256 ~ '^[0-9a-f]{64}$'),
    expected_audience_sha256 text NOT NULL CHECK (expected_audience_sha256 ~ '^[0-9a-f]{64}$'),
    required_provider text NOT NULL DEFAULT 'apple' CHECK (required_provider = 'apple'),
    configured_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- The key is provisioned only by the protected database configuration path. It is
-- retained for completed receipt retries, but is never readable by API roles.
CREATE TABLE IF NOT EXISTS m2a_private.m2a_actor_correlation_keys (
    key_id smallint PRIMARY KEY,
    key_material bytea NOT NULL CHECK (octet_length(key_material) >= 32),
    active boolean NOT NULL DEFAULT true,
    configured_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX IF NOT EXISTS m2a_actor_correlation_keys_one_active_idx
    ON m2a_private.m2a_actor_correlation_keys (active)
    WHERE active;

CREATE TABLE IF NOT EXISTS public.m2a_apple_auth_transactions (
    transaction_id uuid PRIMARY KEY,
    nonce_sha256 text NOT NULL CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    state_sha256 text NOT NULL UNIQUE CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
    callback_sha256 text UNIQUE CHECK (callback_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    purge_after timestamptz NOT NULL,
    completed_at timestamptz,
    CONSTRAINT m2a_apple_auth_transactions_completion_check CHECK (
        (status = 'pending' AND completed_at IS NULL AND callback_sha256 IS NULL)
        OR (status = 'completed' AND completed_at IS NOT NULL AND callback_sha256 IS NOT NULL)
    ),
    CONSTRAINT m2a_apple_auth_transactions_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT m2a_apple_auth_transactions_purge_check CHECK (purge_after >= expires_at)
);

CREATE TABLE IF NOT EXISTS public.m2a_auth_checkpoint_receipts (
    receipt_id uuid PRIMARY KEY,
    transaction_id uuid NOT NULL UNIQUE REFERENCES public.m2a_apple_auth_transactions (transaction_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    actor_correlation_key_id smallint NOT NULL
        REFERENCES m2a_private.m2a_actor_correlation_keys (key_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    actor_correlation_sha256 text NOT NULL CHECK (actor_correlation_sha256 ~ '^[0-9a-f]{64}$'),
    issuer_sha256 text NOT NULL CHECK (issuer_sha256 ~ '^[0-9a-f]{64}$'),
    audience_sha256 text NOT NULL CHECK (audience_sha256 ~ '^[0-9a-f]{64}$'),
    provider text NOT NULL CHECK (provider = 'apple'),
    nonce_sha256 text NOT NULL CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    state_sha256 text NOT NULL UNIQUE CHECK (state_sha256 ~ '^[0-9a-f]{64}$'),
    callback_sha256 text NOT NULL UNIQUE CHECK (callback_sha256 ~ '^[0-9a-f]{64}$'),
    receipt_sha256 text NOT NULL UNIQUE CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status = 'completed'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS m2a_apple_auth_transactions_expiry_idx
    ON public.m2a_apple_auth_transactions (purge_after)
    WHERE status = 'pending';

CREATE OR REPLACE FUNCTION m2a_private.reject_m2a_policy_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'auth checkpoint policy is immutable';
    RETURN NULL;
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.enforce_m2a_transaction_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.completed_at IS NOT NULL OR NEW.callback_sha256 IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'auth checkpoint transaction must begin pending';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'DELETE' THEN
        IF OLD.status = 'pending' AND OLD.purge_after <= clock_timestamp() THEN
            RETURN OLD;
        END IF;

        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint transactions cannot be deleted';
    END IF;

    IF NEW.transaction_id IS DISTINCT FROM OLD.transaction_id
        OR NEW.nonce_sha256 IS DISTINCT FROM OLD.nonce_sha256
        OR NEW.state_sha256 IS DISTINCT FROM OLD.state_sha256
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.purge_after IS DISTINCT FROM OLD.purge_after THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint transaction bindings are immutable';
    END IF;

    IF OLD.status <> 'pending'
        OR NEW.status <> 'completed'
        OR NEW.completed_at IS NULL
        OR NEW.completed_at < OLD.created_at
        OR NEW.callback_sha256 IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint transaction has an invalid transition';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.reject_m2a_receipt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'auth checkpoint receipts are append-only';
    RETURN NULL;
END;
$function$;
CREATE OR REPLACE FUNCTION m2a_private.enforce_m2a_actor_correlation_key_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint correlation keys are immutable';
    END IF;

    IF NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.key_material IS DISTINCT FROM OLD.key_material
        OR NEW.configured_at IS DISTINCT FROM OLD.configured_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint correlation keys are immutable';
    END IF;

    RETURN NEW;
END;
$function$;


DROP TRIGGER IF EXISTS m2a_auth_checkpoint_policy_immutable ON public.m2a_auth_checkpoint_policy;
CREATE TRIGGER m2a_auth_checkpoint_policy_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON public.m2a_auth_checkpoint_policy
    FOR EACH STATEMENT
    EXECUTE FUNCTION m2a_private.reject_m2a_policy_mutation();
DROP TRIGGER IF EXISTS m2a_actor_correlation_keys_immutable ON m2a_private.m2a_actor_correlation_keys;
CREATE TRIGGER m2a_actor_correlation_keys_immutable
    BEFORE UPDATE OR DELETE ON m2a_private.m2a_actor_correlation_keys
    FOR EACH ROW
    EXECUTE FUNCTION m2a_private.enforce_m2a_actor_correlation_key_mutation();

DROP TRIGGER IF EXISTS m2a_apple_auth_transactions_transition ON public.m2a_apple_auth_transactions;
CREATE TRIGGER m2a_apple_auth_transactions_transition
    BEFORE INSERT OR UPDATE OR DELETE ON public.m2a_apple_auth_transactions
    FOR EACH ROW
    EXECUTE FUNCTION m2a_private.enforce_m2a_transaction_transition();

DROP TRIGGER IF EXISTS m2a_apple_auth_transactions_no_truncate ON public.m2a_apple_auth_transactions;
CREATE TRIGGER m2a_apple_auth_transactions_no_truncate
    BEFORE TRUNCATE ON public.m2a_apple_auth_transactions
    FOR EACH STATEMENT
    EXECUTE FUNCTION m2a_private.reject_m2a_receipt_mutation();

DROP TRIGGER IF EXISTS m2a_auth_checkpoint_receipts_immutable ON public.m2a_auth_checkpoint_receipts;
CREATE TRIGGER m2a_auth_checkpoint_receipts_immutable
    BEFORE UPDATE OR DELETE OR TRUNCATE ON public.m2a_auth_checkpoint_receipts
    FOR EACH STATEMENT
    EXECUTE FUNCTION m2a_private.reject_m2a_receipt_mutation();

CREATE OR REPLACE FUNCTION m2a_private.require_sha256(p_digest text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'auth checkpoint binding rejected';
    END IF;

    RETURN p_digest;
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.commit_raw_challenge(p_challenge text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_challenge IS NULL OR p_challenge !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'auth checkpoint binding rejected';
    END IF;

    RETURN encode(extensions.digest(p_challenge, 'sha256'), 'hex');
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.current_apple_actor()
RETURNS TABLE (
    actor_id uuid,
    issuer_sha256 text,
    audience_sha256 text,
    session_issued_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private
AS $function$
DECLARE
    v_claims jsonb := auth.jwt();
    v_actor_claim text;
    v_actor_id uuid;
    v_issuer text;
    v_audience text;
    v_issued_at_claim text;
    v_issued_at_epoch bigint;
    v_expected_issuer_sha256 text;
    v_expected_audience_sha256 text;
    v_required_provider text;
    v_issuer_sha256 text;
    v_audience_sha256 text;
BEGIN
    SELECT policy.expected_issuer_sha256,
           policy.expected_audience_sha256,
           policy.required_provider
      INTO v_expected_issuer_sha256,
           v_expected_audience_sha256,
           v_required_provider
      FROM public.m2a_auth_checkpoint_policy AS policy
     WHERE policy.singleton = 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint is not configured';
    END IF;

    IF jsonb_typeof(v_claims) <> 'object'
        OR v_claims ->> 'role' IS DISTINCT FROM 'authenticated'
        OR jsonb_typeof(v_claims -> 'aud') <> 'string'
        OR jsonb_typeof(v_claims -> 'app_metadata') <> 'object'
        OR v_claims #>> '{app_metadata,provider}' IS DISTINCT FROM v_required_provider THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint authentication context rejected';
    END IF;

    v_actor_claim := NULLIF(v_claims ->> 'sub', '');
    v_issuer := NULLIF(v_claims ->> 'iss', '');
    v_audience := NULLIF(v_claims ->> 'aud', '');
    v_issued_at_claim := NULLIF(v_claims ->> 'iat', '');

    IF v_actor_claim IS NULL
        OR v_actor_claim !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        OR v_issuer IS NULL
        OR v_audience IS NULL
        OR v_issued_at_claim IS NULL
        OR v_issued_at_claim !~ '^[0-9]{1,10}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint authentication context rejected';
    END IF;
    v_issued_at_epoch := v_issued_at_claim::bigint;

    IF v_issued_at_epoch < 0 OR v_issued_at_epoch > 4102444800 THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint authentication context rejected';
    END IF;

    v_actor_id := v_actor_claim::uuid;

    IF auth.uid() IS DISTINCT FROM v_actor_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint authentication context rejected';
    END IF;

    v_issuer_sha256 := encode(extensions.digest(v_issuer, 'sha256'), 'hex');
    v_audience_sha256 := encode(extensions.digest(v_audience, 'sha256'), 'hex');

    IF v_issuer_sha256 <> v_expected_issuer_sha256
        OR v_audience_sha256 <> v_expected_audience_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint authentication context rejected';
    END IF;

    RETURN QUERY SELECT
        v_actor_id,
        v_issuer_sha256,
        v_audience_sha256,
        to_timestamp(v_issued_at_epoch);
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.actor_correlation_sha256(
    p_actor_id uuid,
    p_issuer_sha256 text,
    p_audience_sha256 text,
    p_key_id smallint
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private
AS $function$
DECLARE
    v_key_material bytea;
BEGIN
    SELECT correlation_key.key_material
      INTO v_key_material
      FROM m2a_private.m2a_actor_correlation_keys AS correlation_key
     WHERE correlation_key.key_id = p_key_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint is not configured';
    END IF;

    RETURN encode(
        extensions.hmac(
            convert_to(
                concat_ws(
                    ':',
                    'm2a-apple-actor-correlation-v1',
                    p_actor_id::text,
                    p_issuer_sha256,
                    p_audience_sha256
                ),
                'UTF8'
            ),
            v_key_material,
            'sha256'
        ),
        'hex'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m2a_private.purge_expired_m2a_apple_auth_challenges()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private
AS $function$
BEGIN
    DELETE FROM public.m2a_apple_auth_transactions AS transaction_row
     WHERE transaction_row.status = 'pending'
       AND transaction_row.purge_after <= clock_timestamp();
END;
$function$;

CREATE OR REPLACE FUNCTION public.m2a_begin_apple_auth_checkpoint()
RETURNS TABLE (
    transaction_id uuid,
    nonce text,
    state text,
    expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private
AS $function$
DECLARE
    v_transaction_id uuid := extensions.gen_random_uuid();
    v_nonce text := encode(extensions.gen_random_bytes(32), 'hex');
    v_state text := encode(extensions.gen_random_bytes(32), 'hex');
    v_created_at timestamptz := clock_timestamp();
    v_expires_at timestamptz := v_created_at + interval '10 minutes';
BEGIN
    PERFORM m2a_private.purge_expired_m2a_apple_auth_challenges();

    INSERT INTO public.m2a_apple_auth_transactions (
        transaction_id,
        nonce_sha256,
        state_sha256,
        status,
        created_at,
        expires_at,
        purge_after
    ) VALUES (
        v_transaction_id,
        m2a_private.commit_raw_challenge(v_nonce),
        m2a_private.commit_raw_challenge(v_state),
        'pending',
        v_created_at,
        v_expires_at,
        v_expires_at + interval '1 day'
    );

    RETURN QUERY SELECT v_transaction_id, v_nonce, v_state, v_expires_at;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint challenge generation failed';
END;
$function$;

CREATE OR REPLACE FUNCTION public.m2a_complete_apple_auth_checkpoint(
    p_transaction_id uuid,
    p_nonce text,
    p_state text,
    p_callback_sha256 text
)
RETURNS TABLE (
    receipt_correlation uuid,
    receipt_digest text,
    status text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private
AS $function$
DECLARE
    v_actor record;
    v_transaction public.m2a_apple_auth_transactions%ROWTYPE;
    v_receipt public.m2a_auth_checkpoint_receipts%ROWTYPE;
    v_nonce_sha256 text;
    v_state_sha256 text;
    v_callback_sha256 text;
    v_actor_correlation_key_id smallint;
    v_actor_correlation_sha256 text;
    v_receipt_id uuid := extensions.gen_random_uuid();
    v_receipt_sha256 text;
    v_completed_at timestamptz := clock_timestamp();
BEGIN
    IF p_transaction_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'auth checkpoint binding rejected';
    END IF;

    v_nonce_sha256 := m2a_private.commit_raw_challenge(p_nonce);
    v_state_sha256 := m2a_private.commit_raw_challenge(p_state);
    v_callback_sha256 := m2a_private.require_sha256(p_callback_sha256);

    SELECT * INTO v_actor FROM m2a_private.current_apple_actor();

    SELECT *
      INTO v_transaction
      FROM public.m2a_apple_auth_transactions AS transaction_row
     WHERE transaction_row.transaction_id = p_transaction_id
     FOR UPDATE;

    IF NOT FOUND
        OR v_transaction.nonce_sha256 <> v_nonce_sha256
        OR v_transaction.state_sha256 <> v_state_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'auth checkpoint binding rejected';
    END IF;
    IF v_actor.session_issued_at < to_timestamp(ceil(extract(epoch FROM v_transaction.created_at)))
        OR v_actor.session_issued_at > v_completed_at + interval '5 minutes' THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'auth checkpoint session predates challenge';
    END IF;

    IF v_transaction.status = 'completed' THEN
        SELECT *
          INTO v_receipt
          FROM public.m2a_auth_checkpoint_receipts AS receipt_row
         WHERE receipt_row.transaction_id = p_transaction_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'auth checkpoint transaction is inconsistent';
        END IF;

        v_actor_correlation_sha256 := m2a_private.actor_correlation_sha256(
            v_actor.actor_id,
            v_actor.issuer_sha256,
            v_actor.audience_sha256,
            v_receipt.actor_correlation_key_id
        );

        IF v_receipt.actor_correlation_sha256 <> v_actor_correlation_sha256
            OR v_receipt.issuer_sha256 <> v_actor.issuer_sha256
            OR v_receipt.audience_sha256 <> v_actor.audience_sha256
            OR v_receipt.nonce_sha256 <> v_nonce_sha256
            OR v_receipt.state_sha256 <> v_state_sha256
            OR v_receipt.callback_sha256 <> v_callback_sha256 THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'auth checkpoint binding rejected';
        END IF;

        RETURN QUERY SELECT v_receipt.receipt_id, v_receipt.receipt_sha256, 'completed'::text;
        RETURN;
    END IF;

    IF v_transaction.status <> 'pending' OR v_transaction.expires_at <= v_completed_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint transaction is unavailable';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM public.m2a_apple_auth_transactions AS transaction_row
         WHERE transaction_row.callback_sha256 = v_callback_sha256
           AND transaction_row.transaction_id <> p_transaction_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'auth checkpoint binding rejected';
    END IF;

    SELECT correlation_key.key_id
      INTO v_actor_correlation_key_id
      FROM m2a_private.m2a_actor_correlation_keys AS correlation_key
     WHERE correlation_key.active
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'auth checkpoint is not configured';
    END IF;

    v_actor_correlation_sha256 := m2a_private.actor_correlation_sha256(
        v_actor.actor_id,
        v_actor.issuer_sha256,
        v_actor.audience_sha256,
        v_actor_correlation_key_id
    );

    BEGIN
        UPDATE public.m2a_apple_auth_transactions AS transaction_row
           SET status = 'completed',
               callback_sha256 = v_callback_sha256,
               completed_at = v_completed_at
         WHERE transaction_row.transaction_id = p_transaction_id;
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'auth checkpoint binding rejected';
    END;

    v_receipt_sha256 := encode(
        extensions.digest(
            concat_ws(
                ':',
                'm2a-auth-checkpoint-receipt-v2',
                v_receipt_id::text,
                p_transaction_id::text,
                v_actor_correlation_sha256,
                v_actor.issuer_sha256,
                v_actor.audience_sha256,
                v_nonce_sha256,
                v_state_sha256,
                v_callback_sha256,
                'completed'
            ),
            'sha256'
        ),
        'hex'
    );

    INSERT INTO public.m2a_auth_checkpoint_receipts (
        receipt_id,
        transaction_id,
        actor_correlation_key_id,
        actor_correlation_sha256,
        issuer_sha256,
        audience_sha256,
        provider,
        nonce_sha256,
        state_sha256,
        callback_sha256,
        receipt_sha256,
        status,
        created_at
    ) VALUES (
        v_receipt_id,
        p_transaction_id,
        v_actor_correlation_key_id,
        v_actor_correlation_sha256,
        v_actor.issuer_sha256,
        v_actor.audience_sha256,
        'apple',
        v_nonce_sha256,
        v_state_sha256,
        v_callback_sha256,
        v_receipt_sha256,
        'completed',
        v_completed_at
    );

    RETURN QUERY SELECT v_receipt_id, v_receipt_sha256, 'completed'::text;
END;
$function$;

ALTER TABLE public.m2a_auth_checkpoint_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE m2a_private.m2a_actor_correlation_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m2a_apple_auth_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.m2a_auth_checkpoint_receipts ENABLE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE public.m2a_auth_checkpoint_policy FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE m2a_private.m2a_actor_correlation_keys FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m2a_apple_auth_transactions FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.m2a_auth_checkpoint_receipts FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.reject_m2a_policy_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.enforce_m2a_transaction_transition() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.reject_m2a_receipt_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.enforce_m2a_actor_correlation_key_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.require_sha256(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.commit_raw_challenge(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.current_apple_actor() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.actor_correlation_sha256(uuid, text, text, smallint) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.purge_expired_m2a_apple_auth_challenges() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m2a_begin_apple_auth_checkpoint() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m2a_complete_apple_auth_checkpoint(uuid, text, text, text) FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA m2a_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m2a_auth_checkpoint_policy FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE m2a_private.m2a_actor_correlation_keys FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m2a_apple_auth_transactions FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.m2a_auth_checkpoint_receipts FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.require_sha256(text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.commit_raw_challenge(text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.current_apple_actor() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.actor_correlation_sha256(uuid, text, text, smallint) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.enforce_m2a_actor_correlation_key_mutation() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION m2a_private.purge_expired_m2a_apple_auth_challenges() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m2a_begin_apple_auth_checkpoint() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m2a_complete_apple_auth_checkpoint(uuid, text, text, text) FROM %I', role_name);
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        GRANT EXECUTE ON FUNCTION public.m2a_begin_apple_auth_checkpoint() TO anon;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT EXECUTE ON FUNCTION public.m2a_begin_apple_auth_checkpoint() TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m2a_complete_apple_auth_checkpoint(uuid, text, text, text) TO authenticated;
    END IF;
END;
$block$;

COMMENT ON TABLE public.m2a_auth_checkpoint_policy IS
    'Security-owned SHA-256 claim expectations. It is intentionally empty until protected environment configuration is approved.';
COMMENT ON TABLE m2a_private.m2a_actor_correlation_keys IS
    'Protected HMAC key material for domain-separated actor correlations; API roles have no table privileges.';
COMMENT ON TABLE public.m2a_apple_auth_transactions IS
    'Server-generated one-time Apple auth challenges. Pending rows contain no actor identity and are purged no later than purge_after.';
COMMENT ON TABLE public.m2a_auth_checkpoint_receipts IS
    'Append-only redacted M2A correlation receipts; local fixtures cannot satisfy AUTH-APPLE-STAGING.';

COMMIT;
