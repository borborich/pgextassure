\set ON_ERROR_STOP on

CREATE ROLE shadow_function_owner NOLOGIN;
CREATE ROLE shadow_untrusted_user NOLOGIN;

CREATE SCHEMA trusted AUTHORIZATION shadow_function_owner;
CREATE SCHEMA untrusted AUTHORIZATION shadow_untrusted_user;
GRANT USAGE ON SCHEMA trusted TO shadow_untrusted_user;
GRANT USAGE ON SCHEMA untrusted TO shadow_function_owner;

SET ROLE shadow_function_owner;

CREATE TABLE trusted.execution_log (
    observed_user name NOT NULL
);

CREATE FUNCTION trusted.unsafe_first_part(input text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    RETURN split_part(input, '.', 1);
END
$function$;

CREATE FUNCTION trusted.safe_first_part(input text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN split_part(input, '.', 1);
END
$function$;

CREATE FUNCTION trusted.unsafe_is_on(input text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
BEGIN
    RETURN input IN ('on', 'off');
END
$function$;

CREATE FUNCTION trusted.safe_is_on(input text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    RETURN input IN ('on', 'off');
END
$function$;

GRANT EXECUTE ON FUNCTION trusted.unsafe_first_part(text) TO shadow_untrusted_user;
GRANT EXECUTE ON FUNCTION trusted.safe_first_part(text) TO shadow_untrusted_user;
GRANT EXECUTE ON FUNCTION trusted.unsafe_is_on(text) TO shadow_untrusted_user;
GRANT EXECUTE ON FUNCTION trusted.safe_is_on(text) TO shadow_untrusted_user;

RESET ROLE;
SET ROLE shadow_untrusted_user;

CREATE TABLE untrusted.results (
    unsafe_result text NOT NULL,
    safe_result text NOT NULL,
    unsafe_operator_result boolean NOT NULL,
    safe_operator_result boolean NOT NULL
);

CREATE FUNCTION untrusted.split_part(text, text, integer)
RETURNS text
LANGUAGE sql
AS $function$
    SELECT 'shadowed; effective-user=' || current_user
$function$;

CREATE FUNCTION untrusted.shadow_text_eq(text, text)
RETURNS boolean
LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO trusted.execution_log(observed_user) VALUES (current_user);
    RETURN false;
END
$function$;

CREATE OPERATOR untrusted.= (
    LEFTARG = text,
    RIGHTARG = text,
    FUNCTION = untrusted.shadow_text_eq
);

SET search_path = untrusted, pg_catalog;

INSERT INTO untrusted.results (
    unsafe_result,
    safe_result,
    unsafe_operator_result,
    safe_operator_result
)
VALUES (
    trusted.unsafe_first_part('alpha.beta'),
    trusted.safe_first_part('alpha.beta'),
    trusted.unsafe_is_on('on'),
    trusted.safe_is_on('on')
);

RESET ROLE;

DO $assertions$
DECLARE
    observed untrusted.results%ROWTYPE;
    operator_calls bigint;
    every_operator_call_used_owner boolean;
BEGIN
    SELECT * INTO STRICT observed FROM untrusted.results;
    SELECT count(*), bool_and(observed_user = 'shadow_function_owner')
    INTO STRICT operator_calls, every_operator_call_used_owner
    FROM trusted.execution_log;

    IF observed.unsafe_result <> 'shadowed; effective-user=shadow_function_owner' THEN
        RAISE EXCEPTION 'unexpected unsafe function result: %', observed.unsafe_result;
    END IF;
    IF observed.safe_result <> 'alpha' THEN
        RAISE EXCEPTION 'unexpected safe function result: %', observed.safe_result;
    END IF;
    IF observed.unsafe_operator_result IS NOT FALSE THEN
        RAISE EXCEPTION 'unqualified operator was not shadowed';
    END IF;
    IF observed.safe_operator_result IS NOT TRUE THEN
        RAISE EXCEPTION 'safe operator lookup did not use pg_catalog';
    END IF;
    IF operator_calls < 1 OR every_operator_call_used_owner IS NOT TRUE THEN
        RAISE EXCEPTION
            'shadow operator calls: %, every call used shadow_function_owner: %',
            operator_calls,
            every_operator_call_used_owner;
    END IF;
END
$assertions$;

SELECT 'EXTERNAL_REPRODUCTION|security-definer-shadowing|PASS' AS result;
