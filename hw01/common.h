#pragma once
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOGGER_FD "LOGGER_FD"
#define CONFIG "CONFIG"
#define LD_PRELOAD "LD_PRELOAD"

typedef struct _str_list_n {
    struct _str_list_n *next;
    char *value;
} str_list_t;

typedef struct _filelist_n {
    struct _filelist_n *next;
    FILE *file;
    char *filename;
} filelist_t;

enum { NoneID, OpenID, ReadID, WriteID, GetaddrinfoID, ConnectID, SystemID };

#define perror(msg)         \
    do {                    \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

#define smprintf(...)                                       \
    ({                                                      \
        size_t nbytes = snprintf(NULL, 0, __VA_ARGS__) + 1; \
        char *str = malloc(nbytes);                         \
        snprintf(str, nbytes, __VA_ARGS__);                 \
        str;                                                \
    })

static char *pointerf(const void *p)
{
    if (p)
        return smprintf("%p", p);
    return strdup("0x0");
}

static char *strf(const char *s)
{
    if (!s)
        return strdup("(nil)");
    int size = strlen(s);
    char *content = malloc(2 * strlen(s) + 3);
    int shift = 1;
    content[0] = '\"';
    for (int i = 0; i < size; ++i) {
        if (s[i] == '\n'){
            ++shift;
            content[i + shift - 1] = '\\';
            content[i + shift] = 'n';
        }
        else
            content[i + shift] = s[i];
    }
    content[size + shift] = '\"';
    content[size + shift + 1] = 0;
    
    return content; 
}

static char *pure_fn(const char *fpath)
{
    char *l = strrchr(fpath, '/');
    if (!l)
        l = (char *) fpath;
    else
        ++l;
    char *r = strchr(l, '.');
    if(!r)
        r = l + strlen(l);
    char *ret = malloc(r - l + 1);
    memcpy(ret, l, r - l);
    ret[r - l] = 0;
    return ret;
}