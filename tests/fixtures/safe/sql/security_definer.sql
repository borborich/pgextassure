CREATE SCHEMA IF NOT EXISTS pgextassure_safe;

CREATE FUNCTION pgextassure_safe.current_database_name()
RETURNS name
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT current_database();
$function$;

REVOKE ALL ON FUNCTION pgextassure_safe.current_database_name() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgextassure_safe.current_database_name() TO pgextassure_executor;
