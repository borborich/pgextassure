#include "postgres.h"
#include "fmgr.h"

PG_MODULE_MAGIC;

/*
 * These are examples in prose only: fopen("/etc/passwd"), socket(), system(),
 * popen(), execve(), RegisterBackgroundWorker().
 */
static const char *scanner_noise =
    "File network process BackgroundWorker TcpStream Command unsafe";

PG_FUNCTION_INFO_V1(pgextassure_safe_add_one);

Datum
pgextassure_safe_add_one(PG_FUNCTION_ARGS)
{
    int32 value = PG_GETARG_INT32(0);
    (void) scanner_noise;
    PG_RETURN_INT32(value + 1);
}
