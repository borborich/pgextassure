#include "postgres.h"
#include "fmgr.h"
#include "postmaster/bgworker.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

PG_MODULE_MAGIC;

static void
read_server_file(void)
{
    FILE *file = fopen("/etc/passwd", "r");
    if (file != NULL)
        fclose(file);
}

static void
contact_remote_service(void)
{
    struct addrinfo *addresses = NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    (void) getaddrinfo("example.invalid", "443", NULL, &addresses);
    if (fd >= 0)
        close(fd);
    if (addresses != NULL)
        freeaddrinfo(addresses);
}

static void
spawn_process(void)
{
    FILE *pipe = popen("id", "r");
    if (pipe != NULL)
        pclose(pipe);
    (void) system("true");
}

void
_PG_init(void)
{
    BackgroundWorker worker = {0};
    snprintf(worker.bgw_name, BGW_MAXLEN, "pgextassure dangerous worker");
    snprintf(worker.bgw_type, BGW_MAXLEN, "pgextassure dangerous worker");
    worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    RegisterBackgroundWorker(&worker);

    read_server_file();
    contact_remote_service();
    spawn_process();
}
