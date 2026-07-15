-- Hiker reference-data bootstrap. This migration deliberately excludes user,
-- social, audit, and mutation tables; those arrive in forward-only migrations.
BEGIN;

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

CREATE TYPE public.dataset_release_status AS ENUM ('candidate', 'finalized');

CREATE TABLE public.dataset_manifests (
    dataset_version text PRIMARY KEY CHECK (btrim(dataset_version) <> ''),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    source_url text NOT NULL CHECK (
        source_url ~ '^https://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?:/|$)'
    ),
    source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    mountain_count integer NOT NULL CHECK (mountain_count > 0),
    released_at timestamptz NOT NULL,
    release_status public.dataset_release_status NOT NULL DEFAULT 'candidate',
    CONSTRAINT dataset_manifests_manifest_sha256_key UNIQUE (manifest_sha256)
);

CREATE TABLE public.mountains (
    dataset_version text NOT NULL,
    mountain_id uuid NOT NULL,
    source_identifier text NOT NULL CHECK (btrim(source_identifier) <> ''),
    display_name text NOT NULL CHECK (btrim(display_name) <> ''),
    region text NOT NULL CHECK (btrim(region) <> ''),
    latitude numeric(9, 6) NOT NULL CHECK (latitude BETWEEN -90 AND 90),
    longitude numeric(9, 6) NOT NULL CHECK (longitude BETWEEN -180 AND 180),
    PRIMARY KEY (dataset_version, mountain_id),
    CONSTRAINT mountains_dataset_source_identifier_key
        UNIQUE (dataset_version, source_identifier),
    CONSTRAINT mountains_dataset_version_fkey
        FOREIGN KEY (dataset_version)
        REFERENCES public.dataset_manifests (dataset_version)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION public.enforce_candidate_dataset_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    current_status public.dataset_release_status;
BEGIN
    SELECT manifest.release_status
      INTO current_status
      FROM public.dataset_manifests AS manifest
     WHERE manifest.dataset_version = NEW.dataset_version
     FOR UPDATE;

    IF current_status IS DISTINCT FROM 'candidate'::public.dataset_release_status THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'mountains may be inserted only into a candidate dataset';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.enforce_dataset_manifest_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.release_status <> 'candidate'::public.dataset_release_status THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'dataset manifests must be inserted as candidates';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'dataset manifest rows are immutable',
        HINT = 'A later reviewed migration must introduce the controlled finalization path.';
END;
$function$;

CREATE OR REPLACE FUNCTION public.reject_reference_data_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = format('%I rows are immutable', TG_TABLE_NAME),
        HINT = 'Create a new dataset version through the release-admin import path.';
END;
$function$;

CREATE TRIGGER mountains_candidate_insert
    BEFORE INSERT ON public.mountains
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_candidate_dataset_insert();

CREATE TRIGGER mountains_immutable
    BEFORE UPDATE OR DELETE ON public.mountains
    FOR EACH ROW
    EXECUTE FUNCTION public.reject_reference_data_mutation();

CREATE TRIGGER mountains_no_truncate
    BEFORE TRUNCATE ON public.mountains
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.reject_reference_data_mutation();

CREATE TRIGGER dataset_manifests_transition
    BEFORE INSERT OR UPDATE OR DELETE ON public.dataset_manifests
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_dataset_manifest_transition();

CREATE TRIGGER dataset_manifests_no_truncate
    BEFORE TRUNCATE ON public.dataset_manifests
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.reject_reference_data_mutation();

ALTER TABLE public.dataset_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mountains ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.dataset_manifests IS
    'Candidate-only release metadata; controlled finalization is intentionally deferred to a reviewed migration.';
COMMENT ON TABLE public.mountains IS
    'Versioned immutable reference observations keyed by dataset version and stable mountain ID.';
COMMENT ON COLUMN public.mountains.mountain_id IS
    'Stable opaque identifier reused across dataset versions; never derived from a display name or coordinate.';

-- A later grants/RLS migration revokes anon and authenticated base-table
-- privileges and grants controlled import access only to the release-admin role.
-- This bootstrap intentionally defines no client policies or application grants.
COMMIT;
