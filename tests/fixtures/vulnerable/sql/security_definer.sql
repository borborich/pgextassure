CREATE FUNCTION public.lookup_secret(secret_id bigint)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    -- Unqualified name resolution is attacker-controlled without SET search_path.
    RETURN (SELECT secret_value FROM secrets WHERE id = secret_id);
END;
$function$;
