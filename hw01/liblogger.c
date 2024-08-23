#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "api.h"
#include "hijack.h"

void __attribute__((constructor)) init(void)
{
    logger_fd = strtol(getenv(LOGGER_FD), NULL, 10);
    load_config();

    load_GOT();
    hijack(GOT_entries[OpenID], my_fopen);
    hijack(GOT_entries[ReadID], my_fread);
    hijack(GOT_entries[WriteID], my_fwrite);
    hijack(GOT_entries[ConnectID], my_connect);
    hijack(GOT_entries[GetaddrinfoID], my_getaddrinfo);
    hijack(GOT_entries[SystemID], my_system);
}

void __attribute__((destructor)) fini(void) {}
