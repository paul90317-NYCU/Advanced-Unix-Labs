#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

void unknown_argv()
{
    dprintf(2,
            "Usage: ./logger config.txt [-o file] [-p sopath] command [arg1 "
            "arg2 ...]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int unnamed = 0;
    char buf[1000000];
    setenv(LOGGER_FD, "2", true);
    setenv(LD_PRELOAD, "./logger.so", true);
    char **cmd;
    for (char **arg = argv + 1; arg != argv + argc; ++arg) {
        if (*arg[0] == '-') {
            switch ((*arg)[1]) {
            case 'o': {
                int fd = open(*++arg, O_WRONLY | O_CREAT | O_TRUNC, 0664);
                sprintf(buf, "%d", fd);
                setenv(LOGGER_FD, buf, true);
                break;
            }
            case 'p': {
                setenv(LD_PRELOAD, *++arg, true);
                break;
            default:
                unknown_argv();
            }
            }
        } else {
            if (unnamed++ == 0) {
                setenv(CONFIG, *arg, true);
            } else {
                cmd = arg;
                break;
            }
        }
    }

    if (unnamed != 2)
        unknown_argv();

    execvp(cmd[0], cmd);
}