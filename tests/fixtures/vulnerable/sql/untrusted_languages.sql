CREATE FUNCTION public.run_python(command text)
RETURNS text
LANGUAGE plpython3u
AS $python$
import subprocess
return subprocess.check_output(command, shell=True, text=True)
$python$;

CREATE FUNCTION public.read_with_perl(path text)
RETURNS text
LANGUAGE plperlu
AS $perl$
open my $fh, '<', $_[0] or die $!;
local $/;
return <$fh>;
$perl$;
