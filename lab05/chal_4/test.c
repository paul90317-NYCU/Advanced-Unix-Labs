#include <unistd.h>
int main() {
    char *argv[] = { "cat", "/FLAG", NULL };
    execvp("/usr/bin/cat", argv);
}