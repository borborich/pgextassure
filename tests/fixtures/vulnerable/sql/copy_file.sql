CREATE TABLE public.exported_secrets(secret text);

COPY public.exported_secrets
TO '/tmp/pgextassure-secrets.csv'
WITH (FORMAT csv, HEADER true);
