CREATE TABLE public.command_output(line text);

COPY public.command_output
FROM PROGRAM 'id';
