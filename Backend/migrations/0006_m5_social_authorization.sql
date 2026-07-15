-- M5 social authorization exposes no profile or arbitrary user-discovery surface.
-- Friend codes are the sole discovery capability; all social base tables remain
-- inaccessible to API roles and are reached only through the narrow RPCs below.
BEGIN;

CREATE SCHEMA IF NOT EXISTS m5_private;
REVOKE ALL ON SCHEMA m5_private FROM PUBLIC;

CREATE TYPE public.m5_friendship_state AS ENUM ('pending', 'accepted', 'blocked');

-- The normalized code is retained only so its owner can retrieve the current
-- capability. Lookup uses the unique SHA-256 index and verifies the normalized
-- value as a defense in depth check. A 160-bit random code is not enumerable.
CREATE TABLE public.friend_codes (
    actor_id uuid PRIMARY KEY,
    normalized_code text NOT NULL CHECK (normalized_code ~ '^[0-9A-F]{40}$'),
    code_hash text NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    code_generation bigint NOT NULL DEFAULT 1 CHECK (code_generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    regenerated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE public.friend_code_rate_limits (
    actor_id uuid PRIMARY KEY,
    window_started_at timestamptz NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    updated_at timestamptz NOT NULL
);

-- One row owns the entire social state for a canonical actor pair. No foreign
-- key to profiles is intentional: receiving or sharing a friend code must not
-- create M3 passport state before an M3 passport mutation does so.
CREATE TABLE public.friendships (
    pair_low_actor_id uuid NOT NULL,
    pair_high_actor_id uuid NOT NULL,
    request_id uuid NOT NULL DEFAULT extensions.gen_random_uuid() UNIQUE,
    requested_by_actor_id uuid NOT NULL,
    state public.m5_friendship_state NOT NULL,
    blocked_by_actor_id uuid,
    friend_ref_for_low uuid,
    friend_ref_for_high uuid,
    authorization_generation bigint NOT NULL DEFAULT 0 CHECK (authorization_generation >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (pair_low_actor_id, pair_high_actor_id),
    CHECK (pair_low_actor_id < pair_high_actor_id),
    CHECK (requested_by_actor_id IN (pair_low_actor_id, pair_high_actor_id)),
    CHECK (blocked_by_actor_id IS NULL OR blocked_by_actor_id IN (pair_low_actor_id, pair_high_actor_id)),
    CHECK (
        (state = 'accepted'::public.m5_friendship_state
            AND blocked_by_actor_id IS NULL
            AND friend_ref_for_low IS NOT NULL
            AND friend_ref_for_high IS NOT NULL
            AND authorization_generation > 0)
        OR
        (state <> 'accepted'::public.m5_friendship_state
            AND friend_ref_for_low IS NULL
            AND friend_ref_for_high IS NULL)
    ),
    CHECK (
        (state = 'blocked'::public.m5_friendship_state) = (blocked_by_actor_id IS NOT NULL)
    )
);

-- Each stream is private to exactly one recipient. Stream generation supports
-- fail-closed cursor reset; sequence is monotonic inside that generation.
CREATE TABLE public.friend_revocation_streams (
    recipient_actor_id uuid PRIMARY KEY,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Events deliberately contain neither the actor who revoked access nor a reason.
-- friend_ref is only meaningful to its recipient and is not an actor identifier.
CREATE TABLE public.friend_revocation_events (
    recipient_actor_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    friend_ref uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (recipient_actor_id, generation, sequence),
    UNIQUE (recipient_actor_id, friend_ref, generation, sequence),
    FOREIGN KEY (recipient_actor_id)
        REFERENCES public.friend_revocation_streams (recipient_actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION m5_private.require_social_actor()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
BEGIN
    v_actor_id := m3_private.current_passport_actor();
    IF v_actor_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'social authentication context rejected';
    END IF;

    RETURN v_actor_id;
END;
$function$;

CREATE OR REPLACE FUNCTION m5_private.normalize_friend_code(p_friend_code text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
DECLARE
    v_normalized text;
BEGIN
    IF p_friend_code IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'friend code rejected';
    END IF;

    v_normalized := regexp_replace(upper(btrim(p_friend_code)), '[-[:space:]]', '', 'g');
    IF v_normalized !~ '^[0-9A-F]{40}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'friend code rejected';
    END IF;

    RETURN v_normalized;
END;
$function$;

CREATE OR REPLACE FUNCTION m5_private.friend_code_hash(p_normalized_code text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, extensions
AS $function$
    SELECT encode(extensions.digest(p_normalized_code, 'sha256'), 'hex');
$function$;

CREATE OR REPLACE FUNCTION m5_private.lock_social_actor(p_actor_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('m5-social-actor-v1:' || p_actor_id::text, 0)
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m5_private.lock_friend_pair(
    p_first_actor_id uuid,
    p_second_actor_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
DECLARE
    v_low_actor_id uuid;
    v_high_actor_id uuid;
BEGIN
    IF p_first_actor_id IS NULL
        OR p_second_actor_id IS NULL
        OR p_first_actor_id = p_second_actor_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'friend pair rejected';
    END IF;

    v_low_actor_id := least(p_first_actor_id, p_second_actor_id);
    v_high_actor_id := greatest(p_first_actor_id, p_second_actor_id);
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'm5-friend-pair-v1:' || v_low_actor_id::text || ':' || v_high_actor_id::text,
            0
        )
    );
END;
$function$;

-- Actor locks are acquired in UUID order before the canonical-pair lock. This
-- serializes a pair lifecycle and prevents cross-pair revocation deadlocks.
CREATE OR REPLACE FUNCTION m5_private.lock_social_pair(
    p_first_actor_id uuid,
    p_second_actor_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
DECLARE
    v_low_actor_id uuid;
    v_high_actor_id uuid;
BEGIN
    IF p_first_actor_id IS NULL
        OR p_second_actor_id IS NULL
        OR p_first_actor_id = p_second_actor_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'friend pair rejected';
    END IF;

    v_low_actor_id := least(p_first_actor_id, p_second_actor_id);
    v_high_actor_id := greatest(p_first_actor_id, p_second_actor_id);
    PERFORM m5_private.lock_social_actor(v_low_actor_id);
    PERFORM m5_private.lock_social_actor(v_high_actor_id);
    PERFORM m5_private.lock_friend_pair(v_low_actor_id, v_high_actor_id);
END;
$function$;

CREATE OR REPLACE FUNCTION m5_private.consume_friend_code_budget(p_actor_id uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_window_started_at timestamptz := date_trunc('minute', v_now);
    v_allowed boolean;
BEGIN
    INSERT INTO public.friend_code_rate_limits AS rate_limit (
        actor_id,
        window_started_at,
        attempts,
        updated_at
    ) VALUES (
        p_actor_id,
        v_window_started_at,
        1,
        v_now
    )
    ON CONFLICT (actor_id) DO UPDATE
       SET window_started_at = CASE
               WHEN rate_limit.window_started_at < EXCLUDED.window_started_at
                   THEN EXCLUDED.window_started_at
               ELSE rate_limit.window_started_at
           END,
           attempts = CASE
               WHEN rate_limit.window_started_at < EXCLUDED.window_started_at
                   THEN 1
               ELSE rate_limit.attempts + 1
           END,
           updated_at = EXCLUDED.updated_at
    RETURNING attempts <= 30 INTO v_allowed;

    RETURN v_allowed;
END;
$function$;

CREATE OR REPLACE FUNCTION m5_private.resolve_friend_code(p_normalized_code text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, m5_private, extensions
AS $function$
    SELECT code_row.actor_id
      FROM public.friend_codes AS code_row
     WHERE code_row.code_hash = m5_private.friend_code_hash(p_normalized_code)
       AND code_row.normalized_code = p_normalized_code;
$function$;

CREATE OR REPLACE FUNCTION m5_private.append_friend_revocation(
    p_recipient_actor_id uuid,
    p_friend_ref uuid,
    p_created_at timestamptz
)
RETURNS TABLE (generation bigint, sequence bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m5_private
AS $function$
DECLARE
    v_generation bigint;
    v_sequence bigint;
BEGIN
    INSERT INTO public.friend_revocation_streams (recipient_actor_id)
    VALUES (p_recipient_actor_id)
    ON CONFLICT (recipient_actor_id) DO NOTHING;

    SELECT stream_row.generation, stream_row.last_sequence + 1
      INTO v_generation, v_sequence
      FROM public.friend_revocation_streams AS stream_row
     WHERE stream_row.recipient_actor_id = p_recipient_actor_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'friend revocation stream is unavailable';
    END IF;

    UPDATE public.friend_revocation_streams
       SET last_sequence = v_sequence,
           updated_at = p_created_at
     WHERE recipient_actor_id = p_recipient_actor_id;

    INSERT INTO public.friend_revocation_events (
        recipient_actor_id,
        generation,
        sequence,
        friend_ref,
        created_at
    ) VALUES (
        p_recipient_actor_id,
        v_generation,
        v_sequence,
        p_friend_ref,
        p_created_at
    );

    generation := v_generation;
    sequence := v_sequence;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_get_friend_code()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_code public.friend_codes%ROWTYPE;
    v_normalized_code text;
    v_code_hash text;
BEGIN
    v_actor_id := m5_private.require_social_actor();
    PERFORM m5_private.lock_social_actor(v_actor_id);

    SELECT *
      INTO v_code
      FROM public.friend_codes AS code_row
     WHERE code_row.actor_id = v_actor_id
     FOR UPDATE;
    IF FOUND THEN
        RETURN jsonb_build_object(
            'status', 'ok',
            'friendCode', v_code.normalized_code,
            'codeGeneration', v_code.code_generation
        );
    END IF;

    LOOP
        v_normalized_code := upper(encode(extensions.gen_random_bytes(20), 'hex'));
        v_code_hash := m5_private.friend_code_hash(v_normalized_code);
        BEGIN
            INSERT INTO public.friend_codes (
                actor_id,
                normalized_code,
                code_hash
            ) VALUES (
                v_actor_id,
                v_normalized_code,
                v_code_hash
            )
            RETURNING * INTO v_code;
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            -- A code-hash collision is retried; the actor lock excludes an actor race.
        END;
    END LOOP;

    RETURN jsonb_build_object(
        'status', 'ok',
        'friendCode', v_code.normalized_code,
        'codeGeneration', v_code.code_generation
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_regenerate_friend_code()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_code public.friend_codes%ROWTYPE;
    v_normalized_code text;
    v_code_hash text;
    v_now timestamptz := clock_timestamp();
BEGIN
    v_actor_id := m5_private.require_social_actor();
    PERFORM m5_private.lock_social_actor(v_actor_id);

    LOOP
        v_normalized_code := upper(encode(extensions.gen_random_bytes(20), 'hex'));
        v_code_hash := m5_private.friend_code_hash(v_normalized_code);
        BEGIN
            UPDATE public.friend_codes
               SET normalized_code = v_normalized_code,
                   code_hash = v_code_hash,
                   code_generation = code_generation + 1,
                   regenerated_at = v_now
             WHERE actor_id = v_actor_id
             RETURNING * INTO v_code;

            IF NOT FOUND THEN
                INSERT INTO public.friend_codes (
                    actor_id,
                    normalized_code,
                    code_hash,
                    created_at,
                    regenerated_at
                ) VALUES (
                    v_actor_id,
                    v_normalized_code,
                    v_code_hash,
                    v_now,
                    v_now
                )
                RETURNING * INTO v_code;
            END IF;
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            -- A code-hash collision is retried before reporting a replacement code.
        END;
    END LOOP;

    RETURN jsonb_build_object(
        'status', 'ok',
        'friendCode', v_code.normalized_code,
        'codeGeneration', v_code.code_generation
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_lookup_friend_code(p_friend_code text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_target_actor_id uuid;
    v_normalized_code text;
    v_friendship public.friendships%ROWTYPE;
BEGIN
    v_actor_id := m5_private.require_social_actor();
    BEGIN
        v_normalized_code := m5_private.normalize_friend_code(p_friend_code);
    EXCEPTION WHEN SQLSTATE '22023' THEN
        PERFORM m5_private.lock_social_actor(v_actor_id);
        PERFORM m5_private.consume_friend_code_budget(v_actor_id);
        RETURN jsonb_build_object('status', 'unavailable');
    END;

    v_target_actor_id := m5_private.resolve_friend_code(v_normalized_code);
    IF v_target_actor_id IS NULL OR v_target_actor_id = v_actor_id THEN
        PERFORM m5_private.lock_social_actor(v_actor_id);
        PERFORM m5_private.consume_friend_code_budget(v_actor_id);
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    PERFORM m5_private.lock_social_pair(v_actor_id, v_target_actor_id);
    IF NOT m5_private.consume_friend_code_budget(v_actor_id)
        OR m5_private.resolve_friend_code(v_normalized_code) IS DISTINCT FROM v_target_actor_id THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.pair_low_actor_id = least(v_actor_id, v_target_actor_id)
       AND friendship_row.pair_high_actor_id = greatest(v_actor_id, v_target_actor_id)
     FOR KEY SHARE;

    IF FOUND AND v_friendship.state = 'blocked'::public.m5_friendship_state THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    RETURN jsonb_build_object('status', 'available');
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_send_friend_request(p_friend_code text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_target_actor_id uuid;
    v_normalized_code text;
    v_friendship public.friendships%ROWTYPE;
    v_own_friend_ref uuid;
BEGIN
    v_actor_id := m5_private.require_social_actor();
    BEGIN
        v_normalized_code := m5_private.normalize_friend_code(p_friend_code);
    EXCEPTION WHEN SQLSTATE '22023' THEN
        PERFORM m5_private.lock_social_actor(v_actor_id);
        PERFORM m5_private.consume_friend_code_budget(v_actor_id);
        RETURN jsonb_build_object('status', 'unavailable');
    END;

    v_target_actor_id := m5_private.resolve_friend_code(v_normalized_code);
    IF v_target_actor_id IS NULL OR v_target_actor_id = v_actor_id THEN
        PERFORM m5_private.lock_social_actor(v_actor_id);
        PERFORM m5_private.consume_friend_code_budget(v_actor_id);
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    PERFORM m5_private.lock_social_pair(v_actor_id, v_target_actor_id);
    IF NOT m5_private.consume_friend_code_budget(v_actor_id)
        OR m5_private.resolve_friend_code(v_normalized_code) IS DISTINCT FROM v_target_actor_id THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.pair_low_actor_id = least(v_actor_id, v_target_actor_id)
       AND friendship_row.pair_high_actor_id = greatest(v_actor_id, v_target_actor_id)
     FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO public.friendships (
            pair_low_actor_id,
            pair_high_actor_id,
            requested_by_actor_id,
            state
        ) VALUES (
            least(v_actor_id, v_target_actor_id),
            greatest(v_actor_id, v_target_actor_id),
            v_actor_id,
            'pending'
        )
        RETURNING * INTO v_friendship;

        RETURN jsonb_build_object(
            'status', 'pending',
            'requestRef', v_friendship.request_id
        );
    END IF;

    IF v_friendship.state = 'blocked'::public.m5_friendship_state THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    IF v_friendship.state = 'pending'::public.m5_friendship_state THEN
        IF v_friendship.requested_by_actor_id = v_actor_id THEN
            RETURN jsonb_build_object(
                'status', 'pending',
                'requestRef', v_friendship.request_id
            );
        END IF;

        RETURN jsonb_build_object(
            'status', 'incomingRequest',
            'requestRef', v_friendship.request_id
        );
    END IF;

    v_own_friend_ref := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.friend_ref_for_low
        ELSE v_friendship.friend_ref_for_high
    END;
    RETURN jsonb_build_object(
        'status', 'friends',
        'friendRef', v_own_friend_ref
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_list_incoming_friend_requests()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_requests jsonb;
BEGIN
    v_actor_id := m5_private.require_social_actor();

    SELECT coalesce(
        jsonb_agg(jsonb_build_object('requestRef', friendship_row.request_id)
            ORDER BY friendship_row.created_at, friendship_row.request_id),
        '[]'::jsonb
    )
      INTO v_requests
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'pending'::public.m5_friendship_state
       AND friendship_row.requested_by_actor_id <> v_actor_id
       AND v_actor_id IN (
           friendship_row.pair_low_actor_id,
           friendship_row.pair_high_actor_id
       );

    RETURN jsonb_build_object('status', 'ok', 'requests', v_requests);
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_respond_to_friend_request(
    p_request_ref uuid,
    p_response text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_other_actor_id uuid;
    v_friendship public.friendships%ROWTYPE;
    v_own_friend_ref uuid;
BEGIN
    IF p_request_ref IS NULL
        OR p_response IS NULL
        OR p_response NOT IN ('accept', 'decline') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'friend request response rejected';
    END IF;

    v_actor_id := m5_private.require_social_actor();
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.request_id = p_request_ref
       AND friendship_row.state = 'pending'::public.m5_friendship_state
       AND friendship_row.requested_by_actor_id <> v_actor_id
       AND v_actor_id IN (
           friendship_row.pair_low_actor_id,
           friendship_row.pair_high_actor_id
       );
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    PERFORM m5_private.lock_social_pair(v_actor_id, v_other_actor_id);
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.request_id = p_request_ref
       AND friendship_row.state = 'pending'::public.m5_friendship_state
       AND friendship_row.requested_by_actor_id <> v_actor_id
       AND v_actor_id IN (
           friendship_row.pair_low_actor_id,
           friendship_row.pair_high_actor_id
       )
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    IF p_response = 'decline' THEN
        DELETE FROM public.friendships
         WHERE pair_low_actor_id = v_friendship.pair_low_actor_id
           AND pair_high_actor_id = v_friendship.pair_high_actor_id;
        RETURN jsonb_build_object('status', 'declined', 'requestRef', p_request_ref);
    END IF;

    UPDATE public.friendships
       SET state = 'accepted',
           friend_ref_for_low = extensions.gen_random_uuid(),
           friend_ref_for_high = extensions.gen_random_uuid(),
           authorization_generation = authorization_generation + 1,
           updated_at = clock_timestamp()
     WHERE pair_low_actor_id = v_friendship.pair_low_actor_id
       AND pair_high_actor_id = v_friendship.pair_high_actor_id
     RETURNING * INTO v_friendship;

    v_own_friend_ref := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.friend_ref_for_low
        ELSE v_friendship.friend_ref_for_high
    END;
    RETURN jsonb_build_object(
        'status', 'accepted',
        'friendRef', v_own_friend_ref
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_cancel_friend_request(p_request_ref uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_other_actor_id uuid;
    v_friendship public.friendships%ROWTYPE;
BEGIN
    IF p_request_ref IS NULL THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_actor_id := m5_private.require_social_actor();
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.request_id = p_request_ref
       AND friendship_row.state = 'pending'::public.m5_friendship_state
       AND friendship_row.requested_by_actor_id = v_actor_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    PERFORM m5_private.lock_social_pair(v_actor_id, v_other_actor_id);
    DELETE FROM public.friendships
     WHERE request_id = p_request_ref
       AND state = 'pending'::public.m5_friendship_state
       AND requested_by_actor_id = v_actor_id;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    RETURN jsonb_build_object('status', 'cancelled', 'requestRef', p_request_ref);
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_list_friends()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_friends jsonb;
BEGIN
    v_actor_id := m5_private.require_social_actor();

    SELECT coalesce(
        jsonb_agg(jsonb_build_object(
            'friendRef', CASE
                WHEN friendship_row.pair_low_actor_id = v_actor_id
                    THEN friendship_row.friend_ref_for_low
                ELSE friendship_row.friend_ref_for_high
            END
        ) ORDER BY friendship_row.created_at, friendship_row.request_id),
        '[]'::jsonb
    )
      INTO v_friends
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'accepted'::public.m5_friendship_state
       AND v_actor_id IN (
           friendship_row.pair_low_actor_id,
           friendship_row.pair_high_actor_id
       );

    RETURN jsonb_build_object('status', 'ok', 'friends', v_friends);
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_unfriend(p_friend_ref uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_other_actor_id uuid;
    v_friendship public.friendships%ROWTYPE;
    v_recipient_friend_ref uuid;
BEGIN
    IF p_friend_ref IS NULL THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_actor_id := m5_private.require_social_actor();
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'accepted'::public.m5_friendship_state
       AND (
           (friendship_row.pair_low_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_low = p_friend_ref)
           OR
           (friendship_row.pair_high_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_high = p_friend_ref)
       );
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    PERFORM m5_private.lock_social_pair(v_actor_id, v_other_actor_id);
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'accepted'::public.m5_friendship_state
       AND friendship_row.pair_low_actor_id = least(v_actor_id, v_other_actor_id)
       AND friendship_row.pair_high_actor_id = greatest(v_actor_id, v_other_actor_id)
       AND (
           (friendship_row.pair_low_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_low = p_friend_ref)
           OR
           (friendship_row.pair_high_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_high = p_friend_ref)
       )
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_recipient_friend_ref := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.friend_ref_for_high
        ELSE v_friendship.friend_ref_for_low
    END;
    PERFORM m5_private.append_friend_revocation(
        v_other_actor_id,
        v_recipient_friend_ref,
        clock_timestamp()
    );

    DELETE FROM public.friendships
     WHERE pair_low_actor_id = v_friendship.pair_low_actor_id
       AND pair_high_actor_id = v_friendship.pair_high_actor_id;

    RETURN jsonb_build_object('status', 'unfriended', 'friendRef', p_friend_ref);
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_block_friend(p_reference uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_other_actor_id uuid;
    v_friendship public.friendships%ROWTYPE;
    v_recipient_friend_ref uuid;
    v_result jsonb := jsonb_build_object('status', 'blocked');
BEGIN
    IF p_reference IS NULL THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_actor_id := m5_private.require_social_actor();
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE v_actor_id IN (
               friendship_row.pair_low_actor_id,
               friendship_row.pair_high_actor_id
           )
       AND (
           (friendship_row.state = 'accepted'::public.m5_friendship_state
               AND ((friendship_row.pair_low_actor_id = v_actor_id
                       AND friendship_row.friend_ref_for_low = p_reference)
                   OR (friendship_row.pair_high_actor_id = v_actor_id
                       AND friendship_row.friend_ref_for_high = p_reference)))
           OR
           (friendship_row.state = 'pending'::public.m5_friendship_state
               AND friendship_row.request_id = p_reference)
       );
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    PERFORM m5_private.lock_social_pair(v_actor_id, v_other_actor_id);
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.pair_low_actor_id = least(v_actor_id, v_other_actor_id)
       AND friendship_row.pair_high_actor_id = greatest(v_actor_id, v_other_actor_id)
       AND (
           (friendship_row.state = 'accepted'::public.m5_friendship_state
               AND ((friendship_row.pair_low_actor_id = v_actor_id
                       AND friendship_row.friend_ref_for_low = p_reference)
                   OR (friendship_row.pair_high_actor_id = v_actor_id
                       AND friendship_row.friend_ref_for_high = p_reference)))
           OR
           (friendship_row.state = 'pending'::public.m5_friendship_state
               AND friendship_row.request_id = p_reference)
       )
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    IF v_friendship.state = 'accepted'::public.m5_friendship_state THEN
        v_recipient_friend_ref := CASE
            WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.friend_ref_for_high
            ELSE v_friendship.friend_ref_for_low
        END;
        PERFORM m5_private.append_friend_revocation(
            v_other_actor_id,
            v_recipient_friend_ref,
            clock_timestamp()
        );
        v_result := v_result || jsonb_build_object('friendRef', p_reference);
    END IF;

    UPDATE public.friendships
       SET state = 'blocked',
           blocked_by_actor_id = v_actor_id,
           friend_ref_for_low = NULL,
           friend_ref_for_high = NULL,
           authorization_generation = authorization_generation + 1,
           updated_at = clock_timestamp()
     WHERE pair_low_actor_id = v_friendship.pair_low_actor_id
       AND pair_high_actor_id = v_friendship.pair_high_actor_id;

    RETURN v_result;
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_read_friend_passport(p_friend_ref uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_other_actor_id uuid;
    v_friendship public.friendships%ROWTYPE;
    v_mountains jsonb;
    v_lease_expires_at timestamptz;
BEGIN
    IF p_friend_ref IS NULL THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_actor_id := m5_private.require_social_actor();
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'accepted'::public.m5_friendship_state
       AND (
           (friendship_row.pair_low_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_low = p_friend_ref)
           OR
           (friendship_row.pair_high_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_high = p_friend_ref)
       );
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    PERFORM m5_private.lock_social_pair(v_actor_id, v_other_actor_id);
    SELECT *
      INTO v_friendship
      FROM public.friendships AS friendship_row
     WHERE friendship_row.state = 'accepted'::public.m5_friendship_state
       AND friendship_row.pair_low_actor_id = least(v_actor_id, v_other_actor_id)
       AND friendship_row.pair_high_actor_id = greatest(v_actor_id, v_other_actor_id)
       AND (
           (friendship_row.pair_low_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_low = p_friend_ref)
           OR
           (friendship_row.pair_high_actor_id = v_actor_id
               AND friendship_row.friend_ref_for_high = p_friend_ref)
       )
     FOR KEY SHARE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'unavailable');
    END IF;

    v_other_actor_id := CASE
        WHEN v_friendship.pair_low_actor_id = v_actor_id THEN v_friendship.pair_high_actor_id
        ELSE v_friendship.pair_low_actor_id
    END;
    SELECT coalesce(
        jsonb_agg(jsonb_build_object(
            'mountainId', aggregate_row.mountain_id,
            'visitCount', aggregate_row.visit_count,
            'planState', aggregate_row.plan_state,
            'hasStamp', aggregate_row.stamp_source_visit_id IS NOT NULL,
            'stampVerificationMethod', aggregate_row.stamp_verification_method
        ) ORDER BY known_mountain.ordinal),
        '[]'::jsonb
    )
      INTO v_mountains
      FROM public.passport_aggregates AS aggregate_row
      JOIN public.m3_known_mountains AS known_mountain
        ON known_mountain.mountain_id = aggregate_row.mountain_id
     WHERE aggregate_row.actor_id = v_other_actor_id;

    v_lease_expires_at := clock_timestamp() + interval '30 seconds';
    RETURN jsonb_build_object(
        'status', 'ok',
        'friendRef', p_friend_ref,
        'authorizationGeneration', v_friendship.authorization_generation,
        'leaseExpiresAt', v_lease_expires_at,
        'mountains', v_mountains
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m5_read_revocations(
    p_generation bigint,
    p_after_sequence bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, m5_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_stream public.friend_revocation_streams%ROWTYPE;
    v_events jsonb;
    v_page_sequence bigint;
    v_page_size CONSTANT integer := 256;
BEGIN
    v_actor_id := m5_private.require_social_actor();
    PERFORM m5_private.lock_social_actor(v_actor_id);

    INSERT INTO public.friend_revocation_streams (recipient_actor_id)
    VALUES (v_actor_id)
    ON CONFLICT (recipient_actor_id) DO NOTHING;

    SELECT *
      INTO v_stream
      FROM public.friend_revocation_streams AS stream_row
     WHERE stream_row.recipient_actor_id = v_actor_id
     FOR KEY SHARE;

    IF p_generation IS NULL
        OR p_after_sequence IS NULL
        OR p_generation <> v_stream.generation
        OR p_after_sequence < 0
        OR p_after_sequence > v_stream.last_sequence THEN
        RETURN jsonb_build_object(
            'status', 'gap',
            'generation', v_stream.generation,
            'sequence', v_stream.last_sequence,
            'events', '[]'::jsonb
        );
    END IF;

    SELECT coalesce(
        jsonb_agg(jsonb_build_object(
            'friendRef', event_row.friend_ref,
            'generation', event_row.generation,
            'sequence', event_row.sequence
        ) ORDER BY event_row.sequence),
        '[]'::jsonb
    ),
    coalesce(max(event_row.sequence), p_after_sequence)
      INTO v_events, v_page_sequence
      FROM (
          SELECT
              revocation_event.friend_ref,
              revocation_event.generation,
              revocation_event.sequence
            FROM public.friend_revocation_events AS revocation_event
           WHERE revocation_event.recipient_actor_id = v_actor_id
             AND revocation_event.generation = v_stream.generation
             AND revocation_event.sequence > p_after_sequence
           ORDER BY revocation_event.sequence
           LIMIT v_page_size
      ) AS event_row;

    RETURN jsonb_build_object(
        'status', 'ok',
        'generation', v_stream.generation,
        'sequence', v_page_sequence,
        'events', v_events
    );
END;
$function$;

ALTER TABLE public.friend_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.friend_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE public.friend_code_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.friend_code_rate_limits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.friendships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.friendships FORCE ROW LEVEL SECURITY;
ALTER TABLE public.friend_revocation_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.friend_revocation_streams FORCE ROW LEVEL SECURITY;
ALTER TABLE public.friend_revocation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.friend_revocation_events FORCE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE public.friend_codes FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.friend_code_rate_limits FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.friendships FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.friend_revocation_streams FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.friend_revocation_events FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m5_private FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_get_friend_code() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_regenerate_friend_code() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_lookup_friend_code(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_send_friend_request(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_list_incoming_friend_requests() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_respond_to_friend_request(uuid, text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_cancel_friend_request(uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_list_friends() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_unfriend(uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_block_friend(uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_read_friend_passport(uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m5_read_revocations(bigint, bigint) FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA m5_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.friend_codes FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.friend_code_rate_limits FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.friendships FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.friend_revocation_streams FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.friend_revocation_events FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m5_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_get_friend_code() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_regenerate_friend_code() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_lookup_friend_code(text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_send_friend_request(text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_list_incoming_friend_requests() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_respond_to_friend_request(uuid, text) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_cancel_friend_request(uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_list_friends() FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_unfriend(uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_block_friend(uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_read_friend_passport(uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.m5_read_revocations(bigint, bigint) FROM %I', role_name);
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT EXECUTE ON FUNCTION public.m5_get_friend_code() TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_regenerate_friend_code() TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_lookup_friend_code(text) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_send_friend_request(text) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_list_incoming_friend_requests() TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_respond_to_friend_request(uuid, text) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_cancel_friend_request(uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_list_friends() TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_unfriend(uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_block_friend(uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_read_friend_passport(uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.m5_read_revocations(bigint, bigint) TO authenticated;
    END IF;
END;
$block$;

COMMENT ON TABLE public.friend_codes IS
    'Current high-entropy friend-code capabilities; lookup is hash-indexed and code-only.';
COMMENT ON TABLE public.friendships IS
    'Canonical-pair social authorization state; accepted rows alone authorize aggregate passport reads.';
COMMENT ON TABLE public.friend_revocation_events IS
    'Recipient-only opaque authorization revocations ordered by stream generation and sequence.';

COMMIT;
