\set ON_ERROR_STOP on

CREATE ROLE trigger_function_owner NOLOGIN;
CREATE ROLE trigger_untrusted_user NOLOGIN;

CREATE SCHEMA trusted AUTHORIZATION trigger_function_owner;
CREATE SCHEMA untrusted AUTHORIZATION trigger_untrusted_user;
GRANT USAGE ON SCHEMA trusted TO trigger_untrusted_user;

SET ROLE trigger_function_owner;

CREATE TABLE trusted.execution_log (
    observed_user name NOT NULL,
    observed_operation text NOT NULL
);

CREATE FUNCTION trusted.public_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    INSERT INTO trusted.execution_log(observed_user, observed_operation)
    VALUES (current_user, TG_OP);
    RETURN NEW;
END
$function$;

RESET ROLE;

CREATE TABLE trusted.precondition (
    public_execute_is_effective boolean NOT NULL
);

INSERT INTO trusted.precondition(public_execute_is_effective)
SELECT has_function_privilege(
    'trigger_untrusted_user',
    'trusted.public_trigger()',
    'EXECUTE'
);

SET ROLE trigger_untrusted_user;

CREATE TABLE untrusted.attacker_owned_table (id integer);

CREATE TRIGGER invoke_public_definer_trigger
BEFORE INSERT ON untrusted.attacker_owned_table
FOR EACH ROW
EXECUTE FUNCTION trusted.public_trigger();

INSERT INTO untrusted.attacker_owned_table(id) VALUES (1);

RESET ROLE;

DO $assertions$
DECLARE
    public_execute boolean;
    execution_user name;
    execution_operation text;
BEGIN
    SELECT public_execute_is_effective
    INTO STRICT public_execute
    FROM trusted.precondition;

    SELECT observed_user, observed_operation
    INTO STRICT execution_user, execution_operation
    FROM trusted.execution_log;

    IF public_execute IS NOT TRUE THEN
        RAISE EXCEPTION 'PUBLIC EXECUTE was not effective';
    END IF;
    IF execution_user <> 'trigger_function_owner' THEN
        RAISE EXCEPTION
            'trigger executed as %, expected trigger_function_owner',
            execution_user;
    END IF;
    IF execution_operation <> 'INSERT' THEN
        RAISE EXCEPTION 'unexpected trigger operation: %', execution_operation;
    END IF;
END
$assertions$;

SELECT 'EXTERNAL_REPRODUCTION|security-definer-trigger|PASS' AS result;
