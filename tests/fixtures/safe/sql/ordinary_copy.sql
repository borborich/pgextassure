CREATE TABLE pgextassure_safe.items (
    id bigint PRIMARY KEY,
    label text NOT NULL
);

-- COPY PROGRAM and COPY TO '/tmp/example' are documentation examples only.
COPY pgextassure_safe.items FROM STDIN WITH (FORMAT csv);

SELECT 'LANGUAGE plpython3u; GRANT EXECUTE TO PUBLIC; COPY FROM PROGRAM'
       AS scanner_noise;
