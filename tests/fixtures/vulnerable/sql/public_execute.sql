CREATE FUNCTION public.rotate_application_key()
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT pg_catalog.set_config('pgextassure.application_key', 'rotated', false);
$function$;

GRANT EXECUTE ON FUNCTION public.rotate_application_key() TO PUBLIC;
