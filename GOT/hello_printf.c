/* #include <stdio.h>
#include <sys/types.h>
uid_t getuid(void) {
    fprintf(stderr, "injected getuid, always return 0\n");
    return 0;
}*/

#include <unistd.h> // for write
#include <string.h> // for strlen

int puts (const char *__s) {
    const char *line = "Hello Libary Injection\n";
    size_t len = strlen(line);
    write(1, line, len);
    return 0;
}