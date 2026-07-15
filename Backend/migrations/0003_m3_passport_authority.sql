-- M3 is the server-authoritative passport write model. API roles have no
-- base-table DML: authenticated writes enter only through the four narrow RPCs
-- below, which bind the actor to the validated M2A Apple JWT boundary.
BEGIN;

CREATE SCHEMA IF NOT EXISTS m3_private;
REVOKE ALL ON SCHEMA m3_private FROM PUBLIC;

CREATE TYPE public.passport_plan_state AS ENUM (
    'active_manual',
    'active_auto_completed',
    'manually_removed'
);

CREATE TYPE public.passport_visit_method AS ENUM (
    'manual',
    'gps_verified'
);

CREATE TYPE public.passport_mutation_operation AS ENUM (
    'plan_add',
    'plan_remove',
    'manual_visit_create',
    'manual_visit_delete'
);

CREATE TYPE public.passport_tombstone_kind AS ENUM ('plan', 'visit');

-- This actor root is deliberately minimal. A row is created by the first
-- successful passport mutation and never accepts a client-supplied identity.
CREATE TABLE public.profiles (
    actor_id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE public.passport_global_state (
    actor_id uuid PRIMARY KEY REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    global_version bigint NOT NULL DEFAULT 0 CHECK (global_version >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.m3_known_mountains (
    mountain_id text PRIMARY KEY CHECK (
        btrim(mountain_id) <> '' AND octet_length(mountain_id) <= 512
    ),
    dataset_sha256 text NOT NULL CHECK (dataset_sha256 ~ '^[0-9a-f]{64}$'),
    ordinal smallint NOT NULL UNIQUE CHECK (ordinal BETWEEN 1 AND 100)
);

INSERT INTO public.m3_known_mountains (mountain_id, dataset_sha256, ordinal)
VALUES
    ('hkr_mtn_4d9852ed3a4678b1dab6400733c8fa77', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 1),
    ('hkr_mtn_da12fca46f317ec9c41a81e52a2e18e9', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 2),
    ('hkr_mtn_1895a6994591470aa491de196849d390', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 3),
    ('hkr_mtn_1cbbeefd7f32312dbfd1d5523cbf3a69', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 4),
    ('hkr_mtn_76303cf5d76bcf421d818bd2dfd1a49e', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 5),
    ('hkr_mtn_4e494489053fbd35d7880a8a56ec2a9d', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 6),
    ('hkr_mtn_8e1938d5ea364530de194a28e63d99eb', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 7),
    ('hkr_mtn_ee3cc21f0f3e388f6d63c88e3ada2abd', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 8),
    ('hkr_mtn_3d1c9ebd0553ed18daa92d583bd7598d', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 9),
    ('hkr_mtn_65d017f11deb1e273315b600bbabc53c', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 10),
    ('hkr_mtn_8a5f383ab63263c9282f1f6bce0bce3d', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 11),
    ('hkr_mtn_63978d735a55babc106935c30a0d13e4', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 12),
    ('hkr_mtn_809d36c86a50aa38d5ec12ea871c3fdf', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 13),
    ('hkr_mtn_1b466671c5f4f324eef899136dfbc0ee', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 14),
    ('hkr_mtn_edd48f640a31b899f6f595b29aa0b885', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 15),
    ('hkr_mtn_61ef2c2e719e99a5579cc3affd650c79', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 16),
    ('hkr_mtn_e7827bf51b55845f06b321b70ec3ef72', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 17),
    ('hkr_mtn_b65d4772cdccf15a563bcabfb5f46985', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 18),
    ('hkr_mtn_d27bc996fa8087ea5c92a254670dbe05', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 19),
    ('hkr_mtn_a2d174a7c909e16051f0e90cd1c42c6e', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 20),
    ('hkr_mtn_467038e42ccccaa8a8749eacf86ea65d', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 21),
    ('hkr_mtn_68cafcb3f909b168a981278cbcdb03e6', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 22),
    ('hkr_mtn_ecba1f30d4a4fe662942319e183978a8', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 23),
    ('hkr_mtn_d41f2b8c00f486169cf95acbbc16694c', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 24),
    ('hkr_mtn_61b836d0d388e1cab93898d9b90d0da6', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 25),
    ('hkr_mtn_87f3f9d80feec9521a6cdc71fc574167', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 26),
    ('hkr_mtn_b53c0c8c8d7c475edd90d140f8789781', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 27),
    ('hkr_mtn_307181fa92ce7939bf38e6685599e0f9', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 28),
    ('hkr_mtn_d9bf5bdf1da4dd26b83837c937c67469', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 29),
    ('hkr_mtn_eafbcea454652ac2c81fa37aabe99746', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 30),
    ('hkr_mtn_7abbf7c922d6912df98032066eaee63b', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 31),
    ('hkr_mtn_f5796f196ee35e8b05915644e038176a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 32),
    ('hkr_mtn_4cde4ea4f18bff6d3b8f49b9a08ac2fd', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 33),
    ('hkr_mtn_11d4b9d57b2313f1124b743055fddc45', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 34),
    ('hkr_mtn_d6c12829427bcd9e1c2171943c794e5e', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 35),
    ('hkr_mtn_d21bdddcc87c87d1ef6d699fb009c7bb', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 36),
    ('hkr_mtn_44932d6b12bd74476cf6d4e51baeaf70', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 37),
    ('hkr_mtn_55d3a6abbed6fe2be00aeba1c0bef490', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 38),
    ('hkr_mtn_0d72cdcf67b4ba0f681bb6c6edffb75f', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 39),
    ('hkr_mtn_d23084e1f9cbfa154bd34c41842fa35a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 40),
    ('hkr_mtn_32fce0a4757cfb9da40c1079719b4f06', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 41),
    ('hkr_mtn_8c201dec1c6e05a52b5ceaa3ef4477c4', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 42),
    ('hkr_mtn_2c3d7f44f8118103e33e487c9895f0bf', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 43),
    ('hkr_mtn_e2405b1c8ed8c0b4f5c764d25141ac2a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 44),
    ('hkr_mtn_dca3857b60e74232d7b3ba35115df4a2', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 45),
    ('hkr_mtn_03f343fae9427a772cc169f1fb3c0dd2', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 46),
    ('hkr_mtn_2f90a6878506b434891af6242acd8587', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 47),
    ('hkr_mtn_6895a251ca9f54d39f0c8426bbe1cd8d', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 48),
    ('hkr_mtn_a020240707c3e29409ca036fd4e867be', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 49),
    ('hkr_mtn_f0cc07def5a52b362bec67e001be3849', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 50),
    ('hkr_mtn_81c00948303956822989fe2476634e70', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 51),
    ('hkr_mtn_6706f2033456c933babd9a5a79bde261', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 52),
    ('hkr_mtn_d3b97b24a362b490d3d5fdc665bad1e5', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 53),
    ('hkr_mtn_8b369a7a102199730ca6cd8050c9b4d9', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 54),
    ('hkr_mtn_6312847e5aac0787a625bc0a609a9f78', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 55),
    ('hkr_mtn_2d4a0c039a34453aaa6d1a5cf527eaeb', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 56),
    ('hkr_mtn_61e9d6b555ad0cb31d3789ea8bba22ee', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 57),
    ('hkr_mtn_8c74de3c828060ec4e2a4c2a023ededa', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 58),
    ('hkr_mtn_82f687a122301e6e14add056b43c8026', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 59),
    ('hkr_mtn_42d2f99ed96fed82b9ab66dd49ad5d1a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 60),
    ('hkr_mtn_5529324c66baa32f1917d530fe5f3f78', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 61),
    ('hkr_mtn_b1819d12c9009ba804c02cc35881d35b', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 62),
    ('hkr_mtn_c827a95a70da6c57731e0f62813a2566', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 63),
    ('hkr_mtn_58a801722b33b75b9239565fb72b0e95', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 64),
    ('hkr_mtn_7b31006b93233bb96afa738c24ccbbde', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 65),
    ('hkr_mtn_047e20f4449ff877485fb723dd235551', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 66),
    ('hkr_mtn_f892f4699657d7a0d4e95f07b30a01d0', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 67),
    ('hkr_mtn_e7a6e7287a1e76852af412fc3493c3ad', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 68),
    ('hkr_mtn_b65c8b2d458692ad9c38abba3ee78f83', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 69),
    ('hkr_mtn_a16f021472ce944d84ca6a54b2cfcfbc', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 70),
    ('hkr_mtn_a57ecd44a11598ca162402185b54174a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 71),
    ('hkr_mtn_122937c54d419b1b76f8a466d09e5da9', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 72),
    ('hkr_mtn_3f78c08223a946d9b61e9395b790b9cb', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 73),
    ('hkr_mtn_cafdf3628b0ef8b33775041c8364052e', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 74),
    ('hkr_mtn_6f389a8843894615d3b5d7a4b2a24511', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 75),
    ('hkr_mtn_6c4d0d889c13af5aa41721b9f18224f8', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 76),
    ('hkr_mtn_ddbf15deb04eef64dd8c105fff18bcaa', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 77),
    ('hkr_mtn_cb9a6f374b2315c06ffc069ffe73eea1', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 78),
    ('hkr_mtn_a4efb1bad2d347a5140919900f282760', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 79),
    ('hkr_mtn_3ba23007eae8c2f8581eff5eb37cf002', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 80),
    ('hkr_mtn_74c67615484dba30d6e382c0a6efcd6c', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 81),
    ('hkr_mtn_0beabeda8b5c111c50796a28642c057a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 82),
    ('hkr_mtn_afdbd43fe716de90059ca2346c5a3613', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 83),
    ('hkr_mtn_3d0d4477decb6f20b5b91b7288632208', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 84),
    ('hkr_mtn_be03b0453dabacb436dd30479f4da72f', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 85),
    ('hkr_mtn_bcc590a68c3ddb62c6cf09669a570fbc', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 86),
    ('hkr_mtn_90a55b037c7189a1c7daa672b51f1180', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 87),
    ('hkr_mtn_e5e4eb4fcdc7be4f10692d706ebfaead', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 88),
    ('hkr_mtn_711f764943dd4a7744660bfecc9cc6db', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 89),
    ('hkr_mtn_65e389e11c6bd3f2841fac70f2e6e40b', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 90),
    ('hkr_mtn_249e20b0c61c55d3f2fb75edf4ba6194', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 91),
    ('hkr_mtn_2499d08b7bf6c09c85c2153a65663ebd', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 92),
    ('hkr_mtn_08c6fa772175c930011785b4720e3c94', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 93),
    ('hkr_mtn_d1e3593e5f7045e309e0b2b4f34a606a', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 94),
    ('hkr_mtn_95b50f45bd585888e58dd5591c11919b', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 95),
    ('hkr_mtn_de53709ae72c43f1d803c0ba9f52c657', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 96),
    ('hkr_mtn_65a939c9aaf9500479e00974050025ef', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 97),
    ('hkr_mtn_19e07d72db0d43272496eb737a1546ee', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 98),
    ('hkr_mtn_9e70a7dad415f47cac7d6de09769fc8c', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 99),
    ('hkr_mtn_714454c456205b1077fb2048217c8420', '1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae', 100);

ALTER TABLE public.m3_known_mountains ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE public.m3_known_mountains FROM PUBLIC;
DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES ON TABLE public.m3_known_mountains FROM %I',
                role_name
            );
        END IF;
    END LOOP;
END;
$block$;


-- A row exists for every actor/mountain ever mutated. It is both the
-- projection and the row lock that serializes all aggregate transitions.
CREATE TABLE public.passport_aggregates (
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    visit_count integer NOT NULL DEFAULT 0 CHECK (visit_count >= 0),
    plan_state public.passport_plan_state,
    plan_first_visit_id uuid,
    stamp_source_visit_id uuid,
    stamp_earned_at timestamptz,
    stamp_verification_method public.passport_visit_method,
    aggregate_version bigint NOT NULL DEFAULT 0 CHECK (aggregate_version >= 0),
    global_version bigint NOT NULL DEFAULT 0 CHECK (global_version >= 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (actor_id, mountain_id),
    CONSTRAINT passport_aggregates_plan_state_check CHECK (
        (plan_state = 'active_auto_completed' AND plan_first_visit_id IS NOT NULL)
        OR (plan_state IS DISTINCT FROM 'active_auto_completed' AND plan_first_visit_id IS NULL)
    ),
    CONSTRAINT passport_aggregates_stamp_check CHECK (
        (visit_count = 0
            AND stamp_source_visit_id IS NULL
            AND stamp_earned_at IS NULL
            AND stamp_verification_method IS NULL)
        OR (visit_count > 0
            AND stamp_source_visit_id IS NOT NULL
            AND stamp_earned_at IS NOT NULL
            AND stamp_verification_method IS NOT NULL)
    )
);

-- The plan row preserves a manual removal disposition. Absence means that a
-- mountain has never had a plan; an auto-completed plan retains its first visit
-- until the final remaining visit is deleted.
CREATE TABLE public.passport_plans (
    actor_id uuid NOT NULL,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    plan_state public.passport_plan_state NOT NULL,
    first_visit_id uuid,
    aggregate_version bigint NOT NULL CHECK (aggregate_version >= 0),
    global_version bigint NOT NULL CHECK (global_version >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (actor_id, mountain_id),
    FOREIGN KEY (actor_id, mountain_id)
        REFERENCES public.passport_aggregates (actor_id, mountain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT passport_plans_state_check CHECK (
        (plan_state = 'active_auto_completed' AND first_visit_id IS NOT NULL)
        OR (plan_state IS DISTINCT FROM 'active_auto_completed' AND first_visit_id IS NULL)
    )
);

-- Visit content is immutable. Deletion records visibility metadata on the same
-- audit row and an append-only tombstone; the visit row is never physically
-- removed or rewritten with different visit content.
CREATE TABLE public.passport_visits (
    visit_id uuid PRIMARY KEY,
    actor_id uuid NOT NULL,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    visited_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    verification_method public.passport_visit_method NOT NULL,
    created_aggregate_version bigint NOT NULL CHECK (created_aggregate_version > 0),
    created_global_version bigint NOT NULL CHECK (created_global_version > 0),
    deleted_aggregate_version bigint,
    deleted_global_version bigint,
    deleted_at timestamptz,
    FOREIGN KEY (actor_id, mountain_id)
        REFERENCES public.passport_aggregates (actor_id, mountain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT passport_visits_delete_visibility_check CHECK (
        (deleted_aggregate_version IS NULL
            AND deleted_global_version IS NULL
            AND deleted_at IS NULL)
        OR (deleted_aggregate_version > created_aggregate_version
            AND deleted_global_version > created_global_version
            AND deleted_at IS NOT NULL)
    )
);

CREATE INDEX passport_visits_active_history_idx
    ON public.passport_visits (actor_id, mountain_id, recorded_at, visit_id)
    WHERE deleted_global_version IS NULL;

CREATE TABLE public.passport_stamps (
    actor_id uuid NOT NULL,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    source_visit_id uuid NOT NULL REFERENCES public.passport_visits (visit_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    earned_at timestamptz NOT NULL,
    verification_method public.passport_visit_method NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    global_version bigint NOT NULL CHECK (global_version > 0),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (actor_id, mountain_id),
    FOREIGN KEY (actor_id, mountain_id)
        REFERENCES public.passport_aggregates (actor_id, mountain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE public.passport_tombstones (
    tombstone_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    entity_kind public.passport_tombstone_kind NOT NULL,
    entity_id text NOT NULL CHECK (btrim(entity_id) <> ''),
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    global_version bigint NOT NULL CHECK (global_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    deleted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT passport_tombstones_retention_check CHECK (
        expires_at >= deleted_at + interval '90 days'
    )
);

CREATE INDEX passport_tombstones_actor_version_idx
    ON public.passport_tombstones (actor_id, global_version);
CREATE INDEX passport_tombstones_expiry_idx
    ON public.passport_tombstones (expires_at);

CREATE TABLE public.passport_mutation_receipts (
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    mutation_id uuid NOT NULL,
    operation public.passport_mutation_operation NOT NULL,
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (actor_id, mutation_id),
    CONSTRAINT passport_mutation_receipts_retention_check CHECK (
        expires_at >= created_at + interval '90 days'
    )
);

CREATE INDEX passport_mutation_receipts_expiry_idx
    ON public.passport_mutation_receipts (expires_at);

-- Snapshots are actor-bound, opaque JSON read artifacts. Migration 0004 owns
-- the token and read RPC protocol; this table supplies its durable authority store.
CREATE TABLE public.passport_snapshots (
    snapshot_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    snapshot_version bigint NOT NULL CHECK (snapshot_version > 0),
    global_version bigint NOT NULL CHECK (global_version >= 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT passport_snapshots_actor_version_key UNIQUE (actor_id, snapshot_version),
    CONSTRAINT passport_snapshots_retention_check CHECK (
        expires_at >= created_at + interval '90 days'
    )
);

CREATE INDEX passport_snapshots_expiry_idx ON public.passport_snapshots (expires_at);

-- Exactly one append-only change fact is emitted for every successful mutation,
-- so global_version is an unambiguous actor-bound change cursor.
CREATE TABLE public.passport_changes (
    change_id uuid PRIMARY KEY DEFAULT extensions.gen_random_uuid(),
    actor_id uuid NOT NULL REFERENCES public.profiles (actor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    mountain_id text NOT NULL CHECK (btrim(mountain_id) <> ''),
    operation public.passport_mutation_operation NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    global_version bigint NOT NULL CHECK (global_version > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    result jsonb NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT passport_changes_actor_global_version_key
        UNIQUE (actor_id, global_version),
    CONSTRAINT passport_changes_retention_check CHECK (
        expires_at >= created_at + interval '90 days'
    )
);

CREATE INDEX passport_changes_actor_version_idx
    ON public.passport_changes (actor_id, global_version);
CREATE INDEX passport_changes_expiry_idx ON public.passport_changes (expires_at);

CREATE OR REPLACE FUNCTION m3_private.reject_passport_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = format('%I rows are append-only', TG_TABLE_NAME);
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.enforce_passport_visit_audit_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport visit audit rows cannot be deleted';
    END IF;

    IF OLD.visit_id IS DISTINCT FROM NEW.visit_id
        OR OLD.actor_id IS DISTINCT FROM NEW.actor_id
        OR OLD.mountain_id IS DISTINCT FROM NEW.mountain_id
        OR OLD.visited_at IS DISTINCT FROM NEW.visited_at
        OR OLD.recorded_at IS DISTINCT FROM NEW.recorded_at
        OR OLD.verification_method IS DISTINCT FROM NEW.verification_method
        OR OLD.created_aggregate_version IS DISTINCT FROM NEW.created_aggregate_version
        OR OLD.created_global_version IS DISTINCT FROM NEW.created_global_version
        OR OLD.deleted_global_version IS NOT NULL
        OR OLD.deleted_aggregate_version IS NOT NULL
        OR OLD.deleted_at IS NOT NULL
        OR NEW.deleted_global_version IS NULL
        OR NEW.deleted_aggregate_version IS NULL
        OR NEW.deleted_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport visit audit rows are immutable';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER passport_visits_audit_immutable
    BEFORE UPDATE OR DELETE ON public.passport_visits
    FOR EACH ROW
    EXECUTE FUNCTION m3_private.enforce_passport_visit_audit_update();

CREATE TRIGGER passport_tombstones_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON public.passport_tombstones
    FOR EACH STATEMENT
    EXECUTE FUNCTION m3_private.reject_passport_append_only_mutation();

CREATE TRIGGER passport_mutation_receipts_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON public.passport_mutation_receipts
    FOR EACH STATEMENT
    EXECUTE FUNCTION m3_private.reject_passport_append_only_mutation();

CREATE TRIGGER passport_changes_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON public.passport_changes
    FOR EACH STATEMENT
    EXECUTE FUNCTION m3_private.reject_passport_append_only_mutation();

CREATE OR REPLACE FUNCTION m3_private.require_mountain_id(p_mountain_id text)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    IF p_mountain_id IS NULL
        OR btrim(p_mountain_id) = ''
        OR octet_length(p_mountain_id) > 512
        OR NOT EXISTS (
            SELECT 1
              FROM public.m3_known_mountains AS known
             WHERE known.mountain_id = p_mountain_id
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport mountain identifier rejected';
    END IF;

    RETURN p_mountain_id;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.require_mutation_id(p_mutation_id uuid)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_mutation_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport mutation identifier rejected';
    END IF;

    RETURN p_mutation_id;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.current_passport_actor()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
BEGIN
    SELECT actor.actor_id
      INTO v_actor_id
      FROM m2a_private.current_apple_actor() AS actor;

    IF v_actor_id IS NULL OR auth.uid() IS DISTINCT FROM v_actor_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '28000',
            MESSAGE = 'passport authentication context rejected';
    END IF;

    RETURN v_actor_id;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.lock_passport_actor_root(p_actor_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    INSERT INTO public.profiles (actor_id)
    VALUES (p_actor_id)
    ON CONFLICT (actor_id) DO NOTHING;
    INSERT INTO public.passport_global_state (actor_id)
    VALUES (p_actor_id)
    ON CONFLICT (actor_id) DO NOTHING;

    PERFORM 1
      FROM public.profiles AS profile_row
     WHERE profile_row.actor_id = p_actor_id
     FOR KEY SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport actor root lock is unavailable';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.lock_passport_mutation(
    p_actor_id uuid,
    p_mutation_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            concat_ws(':', 'passport-mutation-v1', p_actor_id::text, p_mutation_id::text),
            0
        )
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.canonical_payload_sha256(p_payload jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, extensions
AS $function$
BEGIN
    IF jsonb_typeof(p_payload) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport mutation payload rejected';
    END IF;

    RETURN encode(extensions.digest(convert_to(p_payload::text, 'UTF8'), 'sha256'), 'hex');
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.replay_passport_mutation_or_reject(
    p_actor_id uuid,
    p_mutation_id uuid,
    p_operation public.passport_mutation_operation,
    p_payload_sha256 text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_receipt public.passport_mutation_receipts%ROWTYPE;
BEGIN
    SELECT *
      INTO v_receipt
      FROM public.passport_mutation_receipts AS receipt_row
     WHERE receipt_row.actor_id = p_actor_id
       AND receipt_row.mutation_id = p_mutation_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    IF v_receipt.operation IS DISTINCT FROM p_operation
        OR v_receipt.payload_sha256 IS DISTINCT FROM p_payload_sha256 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'PT409',
            MESSAGE = 'mutation id replay does not match original request';
    END IF;

    RETURN v_receipt.result;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.lock_passport_aggregate(
    p_actor_id uuid,
    p_mountain_id text
)
RETURNS public.passport_aggregates
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_aggregate public.passport_aggregates%ROWTYPE;
BEGIN
    PERFORM m3_private.lock_passport_actor_root(p_actor_id);

    INSERT INTO public.passport_aggregates (actor_id, mountain_id)
    VALUES (p_actor_id, p_mountain_id)
    ON CONFLICT (actor_id, mountain_id) DO NOTHING;

    SELECT *
      INTO v_aggregate
      FROM public.passport_aggregates AS aggregate_row
     WHERE aggregate_row.actor_id = p_actor_id
       AND aggregate_row.mountain_id = p_mountain_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport aggregate lock is unavailable';
    END IF;

    RETURN v_aggregate;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.next_passport_global_version(
    p_actor_id uuid,
    p_updated_at timestamptz
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_global_version bigint;
BEGIN
    UPDATE public.passport_global_state
       SET global_version = global_version + 1,
           updated_at = p_updated_at
     WHERE actor_id = p_actor_id
     RETURNING global_version INTO v_global_version;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport global version state is unavailable';
    END IF;

    RETURN v_global_version;
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.record_passport_mutation_receipt(
    p_actor_id uuid,
    p_mutation_id uuid,
    p_operation public.passport_mutation_operation,
    p_payload_sha256 text,
    p_result jsonb,
    p_created_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    IF jsonb_typeof(p_result) <> 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'passport mutation result rejected';
    END IF;

    INSERT INTO public.passport_mutation_receipts (
        actor_id,
        mutation_id,
        operation,
        payload_sha256,
        result,
        created_at,
        expires_at
    ) VALUES (
        p_actor_id,
        p_mutation_id,
        p_operation,
        p_payload_sha256,
        p_result,
        p_created_at,
        p_created_at + interval '90 days'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.append_passport_change(
    p_actor_id uuid,
    p_mountain_id text,
    p_operation public.passport_mutation_operation,
    p_aggregate_version bigint,
    p_global_version bigint,
    p_payload jsonb,
    p_result jsonb,
    p_created_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    INSERT INTO public.passport_changes (
        actor_id,
        mountain_id,
        operation,
        aggregate_version,
        global_version,
        payload,
        result,
        created_at,
        expires_at
    ) VALUES (
        p_actor_id,
        p_mountain_id,
        p_operation,
        p_aggregate_version,
        p_global_version,
        p_payload,
        p_result,
        p_created_at,
        p_created_at + interval '90 days'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.append_passport_tombstone(
    p_actor_id uuid,
    p_mountain_id text,
    p_entity_kind public.passport_tombstone_kind,
    p_entity_id text,
    p_aggregate_version bigint,
    p_global_version bigint,
    p_payload jsonb,
    p_deleted_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
BEGIN
    INSERT INTO public.passport_tombstones (
        actor_id,
        mountain_id,
        entity_kind,
        entity_id,
        aggregate_version,
        global_version,
        payload,
        deleted_at,
        expires_at
    ) VALUES (
        p_actor_id,
        p_mountain_id,
        p_entity_kind,
        p_entity_id,
        p_aggregate_version,
        p_global_version,
        p_payload,
        p_deleted_at,
        p_deleted_at + interval '90 days'
    );
END;
$function$;

CREATE OR REPLACE FUNCTION m3_private.passport_result(
    p_operation public.passport_mutation_operation,
    p_mountain_id text,
    p_visit_id uuid,
    p_deleted_visit_id uuid,
    p_aggregate public.passport_aggregates
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m3_private
AS $function$
DECLARE
    v_stamp public.passport_stamps%ROWTYPE;
BEGIN
    SELECT *
      INTO v_stamp
      FROM public.passport_stamps AS stamp_row
     WHERE stamp_row.actor_id = p_aggregate.actor_id
       AND stamp_row.mountain_id = p_mountain_id;

    RETURN jsonb_build_object(
        'operation', p_operation,
        'mountain_id', p_mountain_id,
        'visit_id', p_visit_id,
        'deleted_visit_id', p_deleted_visit_id,
        'visit_count', p_aggregate.visit_count,
        'plan_state', p_aggregate.plan_state,
        'plan_first_visit_id', p_aggregate.plan_first_visit_id,
        'stamp', CASE
            WHEN FOUND THEN jsonb_build_object(
                'source_visit_id', v_stamp.source_visit_id,
                'earned_at', v_stamp.earned_at,
                'verification_method', v_stamp.verification_method
            )
            ELSE NULL
        END,
        'aggregate_version', p_aggregate.aggregate_version,
        'global_version', p_aggregate.global_version
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.passport_add_plan(
    p_mountain_id text,
    p_mutation_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_mountain_id text;
    v_payload jsonb;
    v_payload_sha256 text;
    v_replay jsonb;
    v_aggregate public.passport_aggregates%ROWTYPE;
    v_plan public.passport_plans%ROWTYPE;
    v_has_plan boolean;
    v_now timestamptz;
    v_aggregate_version bigint;
    v_global_version bigint;
    v_result jsonb;
BEGIN
    v_mountain_id := m3_private.require_mountain_id(p_mountain_id);
    PERFORM m3_private.require_mutation_id(p_mutation_id);
    v_actor_id := m3_private.current_passport_actor();
    v_payload := jsonb_build_object('mountain_id', v_mountain_id);
    v_payload_sha256 := m3_private.canonical_payload_sha256(v_payload);

    PERFORM m3_private.lock_passport_mutation(v_actor_id, p_mutation_id);
    v_replay := m3_private.replay_passport_mutation_or_reject(
        v_actor_id, p_mutation_id, 'plan_add', v_payload_sha256
    );
    IF v_replay IS NOT NULL THEN
        RETURN v_replay;
    END IF;

    v_aggregate := m3_private.lock_passport_aggregate(v_actor_id, v_mountain_id);
    IF v_aggregate.visit_count <> 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'cannot add plan for visited mountain';
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
    IF v_has_plan AND v_plan.plan_state <> 'manually_removed' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'plan already exists';
    END IF;

    v_now := clock_timestamp();
    v_aggregate_version := v_aggregate.aggregate_version + 1;
    v_global_version := m3_private.next_passport_global_version(v_actor_id, v_now);

    IF v_has_plan THEN
        UPDATE public.passport_plans
           SET plan_state = 'active_manual',
               first_visit_id = NULL,
               aggregate_version = v_aggregate_version,
               global_version = v_global_version,
               updated_at = v_now
         WHERE actor_id = v_actor_id
           AND mountain_id = v_mountain_id;
    ELSE
        INSERT INTO public.passport_plans (
            actor_id,
            mountain_id,
            plan_state,
            first_visit_id,
            aggregate_version,
            global_version,
            created_at,
            updated_at
        ) VALUES (
            v_actor_id,
            v_mountain_id,
            'active_manual',
            NULL,
            v_aggregate_version,
            v_global_version,
            v_now,
            v_now
        );
    END IF;

    UPDATE public.passport_aggregates
       SET plan_state = 'active_manual',
           plan_first_visit_id = NULL,
           aggregate_version = v_aggregate_version,
           global_version = v_global_version,
           updated_at = v_now
     WHERE actor_id = v_actor_id
       AND mountain_id = v_mountain_id
     RETURNING * INTO v_aggregate;

    v_result := m3_private.passport_result(
        'plan_add', v_mountain_id, NULL, NULL, v_aggregate
    );
    PERFORM m3_private.append_passport_change(
        v_actor_id, v_mountain_id, 'plan_add', v_aggregate_version,
        v_global_version, v_payload, v_result, v_now
    );
    PERFORM m3_private.record_passport_mutation_receipt(
        v_actor_id, p_mutation_id, 'plan_add', v_payload_sha256, v_result, v_now
    );

    RETURN v_result;
END;
$function$;

CREATE OR REPLACE FUNCTION public.passport_remove_plan(
    p_mountain_id text,
    p_mutation_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_mountain_id text;
    v_payload jsonb;
    v_payload_sha256 text;
    v_replay jsonb;
    v_aggregate public.passport_aggregates%ROWTYPE;
    v_plan public.passport_plans%ROWTYPE;
    v_now timestamptz;
    v_aggregate_version bigint;
    v_global_version bigint;
    v_result jsonb;
BEGIN
    v_mountain_id := m3_private.require_mountain_id(p_mountain_id);
    PERFORM m3_private.require_mutation_id(p_mutation_id);
    v_actor_id := m3_private.current_passport_actor();
    v_payload := jsonb_build_object('mountain_id', v_mountain_id);
    v_payload_sha256 := m3_private.canonical_payload_sha256(v_payload);

    PERFORM m3_private.lock_passport_mutation(v_actor_id, p_mutation_id);
    v_replay := m3_private.replay_passport_mutation_or_reject(
        v_actor_id, p_mutation_id, 'plan_remove', v_payload_sha256
    );
    IF v_replay IS NOT NULL THEN
        RETURN v_replay;
    END IF;

    v_aggregate := m3_private.lock_passport_aggregate(v_actor_id, v_mountain_id);
    SELECT *
      INTO v_plan
      FROM public.passport_plans AS plan_row
     WHERE plan_row.actor_id = v_actor_id
       AND plan_row.mountain_id = v_mountain_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'plan not found';
    END IF;
    IF v_aggregate.plan_state IS DISTINCT FROM v_plan.plan_state THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport plan projection is inconsistent';
    END IF;
    IF v_plan.plan_state = 'active_auto_completed' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'cannot remove auto-completed plan';
    END IF;
    IF v_plan.plan_state = 'manually_removed' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'plan already removed';
    END IF;

    v_now := clock_timestamp();
    v_aggregate_version := v_aggregate.aggregate_version + 1;
    v_global_version := m3_private.next_passport_global_version(v_actor_id, v_now);

    UPDATE public.passport_plans
       SET plan_state = 'manually_removed',
           first_visit_id = NULL,
           aggregate_version = v_aggregate_version,
           global_version = v_global_version,
           updated_at = v_now
     WHERE actor_id = v_actor_id
       AND mountain_id = v_mountain_id;

    UPDATE public.passport_aggregates
       SET plan_state = 'manually_removed',
           plan_first_visit_id = NULL,
           aggregate_version = v_aggregate_version,
           global_version = v_global_version,
           updated_at = v_now
     WHERE actor_id = v_actor_id
       AND mountain_id = v_mountain_id
     RETURNING * INTO v_aggregate;

    v_result := m3_private.passport_result(
        'plan_remove', v_mountain_id, NULL, NULL, v_aggregate
    );
    PERFORM m3_private.append_passport_tombstone(
        v_actor_id, v_mountain_id, 'plan', v_mountain_id,
        v_aggregate_version, v_global_version,
        jsonb_build_object('operation', 'plan_remove', 'result', v_result), v_now
    );
    PERFORM m3_private.append_passport_change(
        v_actor_id, v_mountain_id, 'plan_remove', v_aggregate_version,
        v_global_version, v_payload, v_result, v_now
    );
    PERFORM m3_private.record_passport_mutation_receipt(
        v_actor_id, p_mutation_id, 'plan_remove', v_payload_sha256, v_result, v_now
    );

    RETURN v_result;
END;
$function$;

CREATE OR REPLACE FUNCTION public.passport_create_manual_visit(
    p_mountain_id text,
    p_visit_id uuid,
    p_visited_at timestamptz,
    p_mutation_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_mountain_id text;
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
    v_result jsonb;
BEGIN
    v_mountain_id := m3_private.require_mountain_id(p_mountain_id);
    PERFORM m3_private.require_mutation_id(p_mutation_id);
    IF p_visit_id IS NULL OR p_visited_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'manual visit payload rejected';
    END IF;

    v_actor_id := m3_private.current_passport_actor();
    v_payload := jsonb_build_object(
        'mountain_id', v_mountain_id,
        'visit_id', p_visit_id,
        'visited_at', to_char(
            p_visited_at AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )
    );
    v_payload_sha256 := m3_private.canonical_payload_sha256(v_payload);

    PERFORM m3_private.lock_passport_mutation(v_actor_id, p_mutation_id);
    v_replay := m3_private.replay_passport_mutation_or_reject(
        v_actor_id, p_mutation_id, 'manual_visit_create', v_payload_sha256
    );
    IF v_replay IS NOT NULL THEN
        RETURN v_replay;
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

    v_now := clock_timestamp();
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
        'manual',
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
        'manual_visit_create', v_mountain_id, p_visit_id, NULL, v_aggregate
    );
    PERFORM m3_private.append_passport_change(
        v_actor_id, v_mountain_id, 'manual_visit_create', v_aggregate_version,
        v_global_version, v_payload, v_result, v_now
    );
    PERFORM m3_private.record_passport_mutation_receipt(
        v_actor_id, p_mutation_id, 'manual_visit_create', v_payload_sha256,
        v_result, v_now
    );

    RETURN v_result;
END;
$function$;

CREATE OR REPLACE FUNCTION public.passport_delete_manual_visit(
    p_visit_id uuid,
    p_mutation_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, m2a_private, m3_private, extensions
AS $function$
DECLARE
    v_actor_id uuid;
    v_mountain_id text;
    v_payload jsonb;
    v_payload_sha256 text;
    v_replay jsonb;
    v_aggregate public.passport_aggregates%ROWTYPE;
    v_plan public.passport_plans%ROWTYPE;
    v_visit public.passport_visits%ROWTYPE;
    v_stamp_source public.passport_visits%ROWTYPE;
    v_has_plan boolean;
    v_has_stamp_source boolean;
    v_now timestamptz;
    v_aggregate_version bigint;
    v_global_version bigint;
    v_plan_state public.passport_plan_state;
    v_plan_first_visit_id uuid;
    v_result jsonb;
BEGIN
    PERFORM m3_private.require_mutation_id(p_mutation_id);
    IF p_visit_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'manual visit payload rejected';
    END IF;

    v_actor_id := m3_private.current_passport_actor();
    v_payload := jsonb_build_object('visit_id', p_visit_id);
    v_payload_sha256 := m3_private.canonical_payload_sha256(v_payload);

    PERFORM m3_private.lock_passport_mutation(v_actor_id, p_mutation_id);
    v_replay := m3_private.replay_passport_mutation_or_reject(
        v_actor_id, p_mutation_id, 'manual_visit_delete', v_payload_sha256
    );
    IF v_replay IS NOT NULL THEN
        RETURN v_replay;
    END IF;

    SELECT *
      INTO v_visit
      FROM public.passport_visits AS visit_row
     WHERE visit_row.actor_id = v_actor_id
       AND visit_row.visit_id = p_visit_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'visit not found';
    END IF;
    IF v_visit.deleted_global_version IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'visit already deleted';
    END IF;

    v_mountain_id := v_visit.mountain_id;
    v_mountain_id := m3_private.require_mountain_id(v_mountain_id);
    v_aggregate := m3_private.lock_passport_aggregate(v_actor_id, v_mountain_id);
    IF v_aggregate.visit_count <= 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport visit projection is inconsistent';
    END IF;

    SELECT *
      INTO v_plan
      FROM public.passport_plans AS plan_row
     WHERE plan_row.actor_id = v_actor_id
       AND plan_row.mountain_id = v_mountain_id
     FOR UPDATE;
    v_has_plan := FOUND;
    IF (v_has_plan AND (
            v_plan.plan_state IS DISTINCT FROM v_aggregate.plan_state
            OR v_plan.first_visit_id IS DISTINCT FROM v_aggregate.plan_first_visit_id
        ))
        OR (NOT v_has_plan AND v_aggregate.plan_state IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'passport plan projection is inconsistent';
    END IF;

    v_plan_state := v_aggregate.plan_state;
    v_plan_first_visit_id := v_aggregate.plan_first_visit_id;
    IF v_aggregate.visit_count = 1
        AND v_plan_state = 'active_auto_completed' THEN
        v_plan_state := 'active_manual';
        v_plan_first_visit_id := NULL;
    END IF;

    v_now := clock_timestamp();
    v_aggregate_version := v_aggregate.aggregate_version + 1;
    v_global_version := m3_private.next_passport_global_version(v_actor_id, v_now);

    UPDATE public.passport_visits
       SET deleted_aggregate_version = v_aggregate_version,
           deleted_global_version = v_global_version,
           deleted_at = v_now
     WHERE visit_id = p_visit_id
       AND actor_id = v_actor_id;

    IF v_aggregate.visit_count = 1
        AND v_aggregate.plan_state = 'active_auto_completed' THEN
        UPDATE public.passport_plans
           SET plan_state = 'active_manual',
               first_visit_id = NULL,
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
    v_has_stamp_source := FOUND;

    IF v_has_stamp_source THEN
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
    ELSE
        DELETE FROM public.passport_stamps
         WHERE actor_id = v_actor_id
           AND mountain_id = v_mountain_id;
    END IF;

    UPDATE public.passport_aggregates
       SET visit_count = visit_count - 1,
           plan_state = v_plan_state,
           plan_first_visit_id = v_plan_first_visit_id,
           stamp_source_visit_id = CASE
               WHEN v_has_stamp_source THEN v_stamp_source.visit_id ELSE NULL
           END,
           stamp_earned_at = CASE
               WHEN v_has_stamp_source THEN v_stamp_source.recorded_at ELSE NULL
           END,
           stamp_verification_method = CASE
               WHEN v_has_stamp_source THEN v_stamp_source.verification_method ELSE NULL
           END,
           aggregate_version = v_aggregate_version,
           global_version = v_global_version,
           updated_at = v_now
     WHERE actor_id = v_actor_id
       AND mountain_id = v_mountain_id
     RETURNING * INTO v_aggregate;

    v_result := m3_private.passport_result(
        'manual_visit_delete', v_mountain_id, NULL, p_visit_id, v_aggregate
    );
    PERFORM m3_private.append_passport_tombstone(
        v_actor_id, v_mountain_id, 'visit', p_visit_id::text,
        v_aggregate_version, v_global_version,
        jsonb_build_object('operation', 'manual_visit_delete', 'result', v_result), v_now
    );
    PERFORM m3_private.append_passport_change(
        v_actor_id, v_mountain_id, 'manual_visit_delete', v_aggregate_version,
        v_global_version, v_payload, v_result, v_now
    );
    PERFORM m3_private.record_passport_mutation_receipt(
        v_actor_id, p_mutation_id, 'manual_visit_delete', v_payload_sha256,
        v_result, v_now
    );

    RETURN v_result;
END;
$function$;

-- The M2-era names remain read-only compatibility views for clients that only
-- inspect relation existence. All M3 application access uses passport_* names.
CREATE VIEW public.mountain_plans WITH (security_barrier = true) AS
    SELECT * FROM public.passport_plans;
CREATE VIEW public.visit_records WITH (security_barrier = true) AS
    SELECT * FROM public.passport_visits;
CREATE VIEW public.stamps WITH (security_barrier = true) AS
    SELECT * FROM public.passport_stamps;
CREATE VIEW public.mutation_receipts WITH (security_barrier = true) AS
    SELECT * FROM public.passport_mutation_receipts;
CREATE VIEW public.audit_events WITH (security_barrier = true) AS
    SELECT * FROM public.passport_changes;

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_global_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_global_state FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_aggregates FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_visits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_visits FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_stamps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_stamps FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_tombstones ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_tombstones FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_mutation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_mutation_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.passport_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.passport_changes FORCE ROW LEVEL SECURITY;

CREATE POLICY profiles_actor_boundary ON public.profiles
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_aggregates_actor_boundary ON public.passport_aggregates
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_plans_actor_boundary ON public.passport_plans
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_visits_actor_boundary ON public.passport_visits
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_stamps_actor_boundary ON public.passport_stamps
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_tombstones_actor_boundary ON public.passport_tombstones
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_mutation_receipts_actor_boundary ON public.passport_mutation_receipts
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_snapshots_actor_boundary ON public.passport_snapshots
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_changes_actor_boundary ON public.passport_changes
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());
CREATE POLICY passport_global_state_actor_boundary ON public.passport_global_state
    FOR ALL TO PUBLIC
    USING (actor_id = auth.uid())
    WITH CHECK (actor_id = auth.uid());

REVOKE ALL PRIVILEGES ON TABLE public.profiles FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_global_state FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_aggregates FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_plans FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_visits FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_stamps FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_tombstones FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_mutation_receipts FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_snapshots FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.passport_changes FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.mountain_plans FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.visit_records FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.stamps FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.mutation_receipts FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public.audit_events FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m3_private FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.passport_add_plan(text, uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.passport_remove_plan(text, uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) FROM PUBLIC;

DO $block$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL PRIVILEGES ON SCHEMA m3_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.profiles FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_global_state FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_aggregates FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_plans FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_visits FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_stamps FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_tombstones FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_mutation_receipts FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_snapshots FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.passport_changes FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.mountain_plans FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.visit_records FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.stamps FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.mutation_receipts FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.audit_events FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA m3_private FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_add_plan(text, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_remove_plan(text, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) FROM %I', role_name);
            EXECUTE format('REVOKE ALL PRIVILEGES ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) FROM %I', role_name);
        END IF;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT EXECUTE ON FUNCTION public.passport_add_plan(text, uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.passport_remove_plan(text, uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.passport_create_manual_visit(text, uuid, timestamptz, uuid) TO authenticated;
        GRANT EXECUTE ON FUNCTION public.passport_delete_manual_visit(uuid, uuid) TO authenticated;
    END IF;
END;
$block$;

COMMENT ON TABLE public.passport_aggregates IS
    'Actor/mountain lock row and authoritative derived passport projection.';
COMMENT ON TABLE public.passport_visits IS
    'Immutable visit audit content with versioned deletion visibility; never physically deleted.';
COMMENT ON TABLE public.passport_mutation_receipts IS
    'Actor-bound, SHA-256-bound idempotency receipts retained for at least 90 days.';
COMMENT ON TABLE public.passport_changes IS
    'Append-only actor-bound mutation facts retained for at least 90 days.';

COMMIT;
