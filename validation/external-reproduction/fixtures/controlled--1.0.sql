CREATE SCHEMA controlled;

CREATE FUNCTION controlled.unsafe_definer(input text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    RETURN split_part(input, '.', 1);
END
$function$;

CREATE FUNCTION controlled.safe_definer(input text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN pg_catalog.split_part(input, '.', 1);
END
$function$;

CREATE FUNCTION controlled.public_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN NEW;
END
$function$;

CREATE FUNCTION controlled.event_trigger_callback()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN;
END
$function$;

CREATE EVENT TRIGGER controlled_ddl_guard
ON ddl_command_start
EXECUTE FUNCTION controlled.event_trigger_callback();

CREATE FUNCTION controlled.http_get(url text)
RETURNS bigint
LANGUAGE sql
AS $function$
    SELECT 1::bigint
$function$;

SELECT controlled.http_get('https://example.invalid/reproduction');

ALTER FUNCTION controlled.http_get(text) OWNER TO CURRENT_USER;
DROP FUNCTION controlled.http_get(text);
