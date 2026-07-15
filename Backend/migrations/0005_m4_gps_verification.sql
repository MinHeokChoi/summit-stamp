-- M4 GPS verification is online-only and advisory. The supplied sample is evaluated
-- inside this RPC and is deliberately absent from every durable write.
--
-- PostgreSQL makes a newly-added enum label visible after its transaction commits,
-- so keep the label change separate from the transaction that defines its use.
ALTER TYPE public.passport_mutation_operation
    ADD VALUE IF NOT EXISTS 'gps_visit_create';

BEGIN;

CREATE TABLE m3_private.gps_authoritative_summits (
    mountain_id text PRIMARY KEY REFERENCES public.m3_known_mountains (mountain_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    dataset_sha256 text NOT NULL CHECK (dataset_sha256 ~ '^[0-9a-f]{64}$'),
    summit_latitude double precision NOT NULL CHECK (
        summit_latitude BETWEEN -90.0 AND 90.0
    ),
    summit_longitude double precision NOT NULL CHECK (
        summit_longitude BETWEEN -180.0 AND 180.0
    )
);

-- These release-fixed WGS84 representative summit points are bound by ordinal to
-- the M3 authoritative 100-mountain release set. They are not client input.
WITH release_summits (ordinal, summit_latitude, summit_longitude) AS (
    VALUES
        (1, 35.776061466546, 128.16307418154),
        (2, 37.871081735083, 127.9563514253),
        (3, 37.461886512072, 128.56357373348),
        (4, 35.620115657532, 129.00233152567),
        (5, 37.941344043108, 126.96969296809),
        (6, 35.403569455176, 127.04983940625),
        (7, 36.342281668071, 127.20573349073),
        (8, 37.728321025733, 128.46591131957),
        (9, 37.715245218995, 128.01005116445),
        (10, 37.441075705607, 126.96295961955),
        (11, 36.469478243263, 127.86200698944),
        (12, 34.753107414205, 127.9803892479),
        (13, 36.984789116805, 128.25666733208),
        (14, 36.091608095519, 128.29982883577),
        (15, 35.280149440475, 129.05059247485),
        (16, 34.697100350902, 125.20419722543),
        (17, 35.837884124064, 129.26428743774),
        (18, 36.278893976271, 129.28940254045),
        (19, 35.47821546869, 126.88918533667),
        (20, 36.12339720131, 127.3193364728),
        (21, 38.210983253273, 128.13475646366),
        (22, 36.668959232363, 127.92941350323),
        (23, 36.671466315004, 126.62399767196),
        (24, 35.859465253376, 127.74632944442),
        (25, 37.308715480714, 129.01250274001),
        (26, 36.85638799762, 128.31107007734),
        (27, 37.696856053973, 127.01049726987),
        (28, 34.473198579652, 126.63654649275),
        (29, 37.426410080877, 129.00469941929),
        (30, 37.61262921996, 126.43464112863),
        (31, 35.761087002171, 127.41622089185),
        (32, 38.104281641602, 127.33800199362),
        (33, 37.941382830518, 127.43213164738),
        (34, 35.728077216298, 127.08510225373),
        (35, 35.124338292558, 127.00888909751),
        (36, 35.210050543489, 128.53553010285),
        (37, 34.810421993098, 128.41614868894),
        (38, 36.039399120866, 127.8491099539),
        (39, 35.455587939506, 126.7543191371),
        (40, 37.888291945644, 128.38999949102),
        (41, 37.396539584862, 128.29362377726),
        (42, 35.460687014988, 126.86877382046),
        (43, 38.074894384605, 127.44429505225),
        (44, 35.106219628582, 127.62111722316),
        (45, 37.280101808124, 128.59614465873),
        (46, 35.635588215816, 126.62175137021),
        (47, 37.658651963852, 126.97798955973),
        (48, 35.715609656162, 128.52425977588),
        (49, 37.839808333104, 127.66052551833),
        (50, 36.220724500398, 127.53834143079),
        (51, 35.480685998883, 126.51066314051),
        (52, 38.118990260658, 128.46517898891),
        (53, 37.500764979463, 130.86609240959),
        (54, 36.957366338597, 128.48436016929),
        (55, 37.937180967491, 127.08703880258),
        (56, 36.542746994943, 127.87045000709),
        (57, 35.539734212529, 129.05253866344),
        (58, 35.070960681187, 128.2649724531),
        (59, 37.794123883855, 128.54305009751),
        (60, 38.000576831001, 127.80407346088),
        (61, 37.5611282524, 127.5456720571),
        (62, 38.038245432721, 127.7473001423),
        (63, 35.615687610055, 128.9595335241),
        (64, 37.876811895238, 127.32521144475),
        (65, 35.911389770846, 127.35760521261),
        (66, 36.885783985627, 128.1056433222),
        (67, 34.76654990013, 126.70404406988),
        (68, 37.575393020057, 127.48681082019),
        (69, 37.076542618902, 129.23020904252),
        (70, 35.629162776809, 127.59481089873),
        (71, 35.560870444785, 128.97090452281),
        (72, 35.946354569016, 127.68952183187),
        (73, 38.048737563651, 128.42541735954),
        (74, 35.001181981131, 127.31348735665),
        (75, 36.389524560657, 129.16274449475),
        (76, 36.788258675145, 128.10093682404),
        (77, 35.337074704527, 127.73059999392),
        (78, 34.846026433788, 128.1853167084),
        (79, 34.531600197989, 126.91846615035),
        (80, 37.679977266497, 127.27266540726),
        (81, 35.330981353402, 128.98524580118),
        (82, 36.15921283487, 127.59994438024),
        (83, 36.794336158809, 128.90878012155),
        (84, 35.400068762402, 126.97630281537),
        (85, 37.752627853341, 127.3339495326),
        (86, 37.365104701187, 128.05541649631),
        (87, 36.412860243811, 126.88479158788),
        (88, 37.098448455373, 128.91608680274),
        (89, 37.117477912866, 128.4852014113),
        (90, 36.016289713618, 128.69455391715),
        (91, 37.695948814016, 127.69656438122),
        (92, 34.617373488429, 127.43576965246),
        (93, 33.361280986044, 126.52998077415),
        (94, 37.995270894234, 127.50376118673),
        (95, 35.546766232553, 128.53252787705),
        (96, 35.495088517673, 127.97438998834),
        (97, 35.655188386086, 127.75542766325),
        (98, 36.118295162864, 127.96626085624),
        (99, 36.812523711419, 128.27795653759),
        (100, 36.714762803595, 128.00461365014)
)
INSERT INTO m3_private.gps_authoritative_summits (
    mountain_id,
    dataset_sha256,
    summit_latitude,
    summit_longitude
)
SELECT known.mountain_id,
       known.dataset_sha256,
       release_summits.summit_latitude,
       release_summits.summit_longitude
  FROM public.m3_known_mountains AS known
  JOIN release_summits USING (ordinal);

CREATE OR REPLACE FUNCTION m3_private.assert_gps_summit_release()
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    IF (SELECT count(*) FROM m3_private.gps_authoritative_summits) <> 100
        OR EXISTS (
            SELECT 1
              FROM public.m3_known_mountains AS known
              LEFT JOIN m3_private.gps_authoritative_summits AS summit
                ON summit.mountain_id = known.mountain_id
               AND summit.dataset_sha256 = known.dataset_sha256
             WHERE summit.mountain_id IS NULL
        )
        OR (
            SELECT encode(
                extensions.digest(
                    string_agg(
                        summit.mountain_id || ':' ||
                        summit.summit_latitude::text || ':' ||
                        summit.summit_longitude::text,
                        E'\n' ORDER BY summit.mountain_id
                    ),
                    'sha256'
                ),
                'hex'
            )
              FROM m3_private.gps_authoritative_summits AS summit
        ) IS DISTINCT FROM '5d9f916018cf85eaf0583677f542c3c3dd3a0ff52501ea22ff6146d6b59714f8' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport GPS summit set is unavailable';
    END IF;
END;
$function$;

SELECT m3_private.assert_gps_summit_release();

CREATE OR REPLACE FUNCTION m3_private.require_gps_api_version(p_api_version text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_api_version IS DISTINCT FROM 'm4-v1' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport GPS API version rejected';
    END IF;

    RETURN p_api_version;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.gps_manual_fallback(p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_reason NOT IN (
        'gps_sample_invalid',
        'gps_sample_age_rejected',
        'gps_accuracy_rejected',
        'gps_distance_rejected'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport GPS result rejected';
    END IF;

    RETURN jsonb_build_object(
        'status', 'manual_fallback',
        'manual_fallback', true,
        'reason', p_reason
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.m4_create_gps_visit(
    p_api_version text,
    p_dataset_sha256 text,
    p_history_token text,
    p_mountain_id text,
    p_visit_id uuid,
    p_visited_at timestamptz,
    p_mutation_id uuid,
    p_latitude double precision,
    p_longitude double precision,
    p_horizontal_accuracy_m double precision,
    p_sampled_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_api_version text;
    v_dataset_sha256 text;
    v_history_token public.m3_history_tokens%ROWTYPE;
    v_mountain_id text;
    v_summit m3_private.gps_authoritative_summits%ROWTYPE;
    v_payload jsonb;
    v_payload_sha256 text;
    v_replay jsonb;
    v_aggregate public.passport_aggregates%ROWTYPE;
    v_plan public.passport_plans%ROWTYPE;
    v_existing_visit public.passport_visits%ROWTYPE;
    v_stamp_source public.passport_visits%ROWTYPE;
    v_has_plan boolean;
    v_now timestamptz;
    v_aggregate_version bigint;
    v_global_version bigint;
    v_plan_state public.passport_plan_state;
    v_plan_first_visit_id uuid;
    v_delta_latitude double precision;
    v_delta_longitude double precision;
    v_haversine_a double precision;
    v_distance_m double precision;
    v_result jsonb;
BEGIN
    v_api_version := m3_private.require_gps_api_version(p_api_version);
    v_dataset_sha256 := m3_private.require_sync_dataset_sha256(p_dataset_sha256);
    v_actor_id := m3_private.current_passport_actor();
    v_history_token := m3_private.require_history_token(p_history_token, v_actor_id);

    IF v_history_token.dataset_sha256 IS DISTINCT FROM v_dataset_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'passport GPS capability binding rejected';
    END IF;

    PERFORM m3_private.assert_current_known_dataset(v_dataset_sha256);
    PERFORM m3_private.assert_gps_summit_release();
    v_mountain_id := m3_private.require_known_mountain(
        p_mountain_id, v_dataset_sha256
    );
    PERFORM m3_private.require_mutation_id(p_mutation_id);
    IF p_visit_id IS NULL OR p_visited_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport GPS visit payload rejected';
    END IF;

    SELECT *
      INTO v_summit
      FROM m3_private.gps_authoritative_summits AS summit
     WHERE summit.mountain_id = v_mountain_id
       AND summit.dataset_sha256 = v_dataset_sha256
     FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport GPS summit binding rejected';
    END IF;

    -- Deliberately durable only: all one-shot sample fields remain transient.
    v_payload := jsonb_build_object(
        'api_version', v_api_version,
        'dataset_sha256', v_dataset_sha256,
        'mountain_id', v_mountain_id,
        'verification_method', 'gps_verified',
        'visit_id', p_visit_id,
        'visited_at', to_char(
            p_visited_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )
    );
    v_payload_sha256 := m3_private.canonical_payload_sha256(v_payload);

    PERFORM m3_private.lock_passport_mutation(v_actor_id, p_mutation_id);
    v_replay := m3_private.replay_passport_mutation_or_reject(
        v_actor_id, p_mutation_id, 'gps_visit_create', v_payload_sha256
    );
    IF v_replay IS NOT NULL THEN
        RETURN v_replay;
    END IF;

    IF p_latitude IS NULL
        OR p_longitude IS NULL
        OR p_latitude NOT BETWEEN -90.0 AND 90.0
        OR p_longitude NOT BETWEEN -180.0 AND 180.0 THEN
        RETURN m3_private.gps_manual_fallback('gps_sample_invalid');
    END IF;
    IF p_horizontal_accuracy_m IS NULL
        OR p_horizontal_accuracy_m NOT BETWEEN 0.0 AND 100.0 THEN
        RETURN m3_private.gps_manual_fallback('gps_accuracy_rejected');
    END IF;

    -- Statement start makes the inclusive age boundary stable for this request.
    v_now := statement_timestamp();
    IF p_sampled_at IS NULL
        OR p_sampled_at > v_now
        OR p_sampled_at < v_now - interval '120 seconds' THEN
        RETURN m3_private.gps_manual_fallback('gps_sample_age_rejected');
    END IF;

    v_delta_latitude := radians(p_latitude - v_summit.summit_latitude);
    v_delta_longitude := radians(p_longitude - v_summit.summit_longitude);
    v_haversine_a := power(sin(v_delta_latitude / 2.0), 2.0)
        + cos(radians(v_summit.summit_latitude))
        * cos(radians(p_latitude))
        * power(sin(v_delta_longitude / 2.0), 2.0);
    v_distance_m := 6371008.8 * 2.0 * atan2(
        sqrt(greatest(0.0, v_haversine_a)),
        sqrt(greatest(0.0, 1.0 - v_haversine_a))
    );
    IF v_distance_m > 300.0 THEN
        RETURN m3_private.gps_manual_fallback('gps_distance_rejected');
    END IF;

    v_aggregate := m3_private.lock_passport_aggregate(v_actor_id, v_mountain_id);
    SELECT *
      INTO v_existing_visit
      FROM public.passport_visits AS visit_row
     WHERE visit_row.visit_id = p_visit_id
     FOR UPDATE;
    IF FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'visit id already exists';
    END IF;

    SELECT *
      INTO v_plan
      FROM public.passport_plans AS plan_row
     WHERE plan_row.actor_id = v_actor_id
       AND plan_row.mountain_id = v_mountain_id
     FOR UPDATE;
    v_has_plan := FOUND;
    IF (v_has_plan AND v_aggregate.plan_state IS DISTINCT FROM v_plan.plan_state)
        OR (NOT v_has_plan AND v_aggregate.plan_state IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport plan projection is inconsistent';
    END IF;

    v_plan_state := v_aggregate.plan_state;
    v_plan_first_visit_id := v_aggregate.plan_first_visit_id;
    IF v_plan_state = 'active_manual' THEN
        IF NOT v_has_plan THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'passport plan projection is inconsistent';
        END IF;
        v_plan_state := 'active_auto_completed';
        v_plan_first_visit_id := p_visit_id;
    END IF;

    v_aggregate_version := v_aggregate.aggregate_version + 1;
    v_global_version := m3_private.next_passport_global_version(v_actor_id, v_now);

    INSERT INTO public.passport_visits (
        visit_id,
        actor_id,
        mountain_id,
        visited_at,
        recorded_at,
        verification_method,
        created_aggregate_version,
        created_global_version
    ) VALUES (
        p_visit_id,
        v_actor_id,
        v_mountain_id,
        p_visited_at,
        v_now,
        'gps_verified',
        v_aggregate_version,
        v_global_version
    );

    IF v_aggregate.plan_state = 'active_manual' THEN
        UPDATE public.passport_plans
           SET plan_state = 'active_auto_completed',
               first_visit_id = p_visit_id,
               aggregate_version = v_aggregate_version,
               global_version = v_global_version,
               updated_at = v_now
         WHERE actor_id = v_actor_id
           AND mountain_id = v_mountain_id;
    END IF;

    SELECT *
      INTO v_stamp_source
      FROM public.passport_visits AS visit_row
     WHERE visit_row.actor_id = v_actor_id
       AND visit_row.mountain_id = v_mountain_id
       AND visit_row.deleted_global_version IS NULL
     ORDER BY visit_row.recorded_at ASC, visit_row.visit_id ASC
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport stamp source is unavailable';
    END IF;

    INSERT INTO public.passport_stamps (
        actor_id,
        mountain_id,
        source_visit_id,
        earned_at,
        verification_method,
        aggregate_version,
        global_version,
        updated_at
    ) VALUES (
        v_actor_id,
        v_mountain_id,
        v_stamp_source.visit_id,
        v_stamp_source.recorded_at,
        v_stamp_source.verification_method,
        v_aggregate_version,
        v_global_version,
        v_now
    ) ON CONFLICT (actor_id, mountain_id) DO UPDATE
        SET source_visit_id = EXCLUDED.source_visit_id,
            earned_at = EXCLUDED.earned_at,
            verification_method = EXCLUDED.verification_method,
            aggregate_version = EXCLUDED.aggregate_version,
            global_version = EXCLUDED.global_version,
            updated_at = EXCLUDED.updated_at;

    UPDATE public.passport_aggregates
       SET visit_count = visit_count + 1,
           plan_state = v_plan_state,
           plan_first_visit_id = v_plan_first_visit_id,
           stamp_source_visit_id = v_stamp_source.visit_id,
           stamp_earned_at = v_stamp_source.recorded_at,
           stamp_verification_method = v_stamp_source.verification_method,
           aggregate_version = v_aggregate_version,
           global_version = v_global_version,
           updated_at = v_now
     WHERE actor_id = v_actor_id
       AND mountain_id = v_mountain_id
     RETURNING * INTO v_aggregate;

    v_result := m3_private.passport_result(
        'gps_visit_create', v_mountain_id, p_visit_id, NULL, v_aggregate
    ) || jsonb_build_object(
        'status', 'gps_verified',
        'manual_fallback', false,
        'verification_method', 'gps_verified'
    );
    PERFORM m3_private.append_passport_change(
        v_actor_id, v_mountain_id, 'gps_visit_create', v_aggregate_version,
        v_global_version, v_payload, v_result, v_now
    );
    PERFORM m3_private.record_passport_mutation_receipt(
        v_actor_id, p_mutation_id, 'gps_visit_create', v_payload_sha256,
        v_result, v_now
    );

    RETURN v_result;
END;
$function$;

ALTER TABLE m3_private.gps_authoritative_summits ENABLE ROW LEVEL SECURITY;

REVOKE ALL PRIVILEGES ON TABLE m3_private.gps_authoritative_summits FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.m4_create_gps_visit(
    text, text, text, text, uuid, timestamptz, uuid, double precision,
    double precision, double precision, timestamptz
) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m3_private.require_gps_api_version(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m3_private.gps_manual_fallback(text) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION m3_private.assert_gps_summit_release() FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE m3_private.gps_authoritative_summits FROM %I',
                role_name
            );
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON FUNCTION public.m4_create_gps_visit(text, text, text, text, uuid, timestamptz, uuid, double precision, double precision, double precision, timestamptz) FROM %I',
                role_name
            );
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT EXECUTE ON FUNCTION public.m4_create_gps_visit(
            text, text, text, text, uuid, timestamptz, uuid, double precision,
            double precision, double precision, timestamptz
        ) TO authenticated;
    END IF;
END;
$block$;

COMMENT ON TABLE m3_private.gps_authoritative_summits IS
    'Release-fixed authoritative summit points for transient M4 advisory GPS evaluation; never API-readable.';
COMMENT ON FUNCTION public.m4_create_gps_visit(
    text, text, text, text, uuid, timestamptz, uuid, double precision,
    double precision, double precision, timestamptz
) IS
    'Authenticated online-only M4 advisory GPS visit RPC. Raw sample coordinates, accuracy, and sampled timestamp are never durable.';

COMMIT;
