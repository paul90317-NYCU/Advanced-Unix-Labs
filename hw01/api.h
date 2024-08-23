#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
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
#include <sys/stat.h>

#include "common.h"

static str_list_t *blacklists[6] = {0};

static filelist_t *files;

typedef FILE *(* fopen_t)(const char *__restrict, const char *__restrict);
typedef ssize_t (* fwrite_t)(const void *__restrict, size_t __size, size_t, FILE *__restrict);
typedef ssize_t (* fread_t)(void *__restrict, size_t, size_t, FILE *__restrict);
typedef int (* connect_t)(int, const struct sockaddr *, socklen_t);
typedef int (* getaddrinfo_t)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);

static int logger_fd;

static void new_file(FILE *file, const char *filename)
{
    filelist_t *list =
        (filelist_t *) malloc(sizeof(str_list_t));
    //printf("insert %p %s\n", file, filename);
    list->filename = strdup(filename);
    strcpy(list->filename, filename);
    list->next = files;
    files = list;
    list->file = file;
    return;
}

static void rm_file(FILE *file)
{
    filelist_t **last = &files, *curr;
    for (curr = files; curr; curr = curr->next) {
        if (curr->file == file) {
            *last = curr->next;
            free(curr->filename);
            free(curr);
            return;
        }
        last = &curr->next;
    }
}

static char *get_filename(FILE *file)
{
    for (filelist_t *curr = files; curr; curr = curr->next) {
        if (curr->file == file) {
            return curr->filename;
        }
    }
    return NULL;
}

static str_list_t *new_blacklist(char *buf, str_list_t *next)
{
    str_list_t *list =
        (str_list_t *) malloc(sizeof(str_list_t) + strlen(buf) + 1);
    list->value = (char *) &list[1];
    strcpy(list->value, buf);
    list->next = next;
    return list;
}

static ssize_t getline0(char **__restrict__ __lineptr,
                        size_t *__restrict__ __n,
                        FILE *__restrict__ __stream)
{
    ssize_t ret = getline(__lineptr, __n, __stream);
    char *back = *__lineptr + ret - 1;
    while (*back == 'r' || *back == '\n') {
        *(back--) = 0;
        --ret;
    }
    return ret;
}

static void load_config()
{
    FILE *file = fopen(getenv("CONFIG"), "r");
    if (!file)
        perror("load_config()");
    int state = NoneID;
    char *line = NULL;
    size_t len = 0;
    while (getline0(&line, &len, file) != -1) {
        if (!strcmp(line, "BEGIN open-blacklist")) {
            state = OpenID;
            continue;
        }
        if (!strcmp(line, "BEGIN read-blacklist")) {
            state = ReadID;
            continue;
        }
        if (!strcmp(line, "BEGIN write-blacklist")) {
            state = WriteID;
            continue;
        }
        if (!strcmp(line, "BEGIN connect-blacklist")) {
            state = ConnectID;
            continue;
        }
        if (!strcmp(line, "BEGIN getaddrinfo-blacklist")) {
            state = GetaddrinfoID;
            continue;
        }
        if (!strncmp(line, "END open-blacklist", 3) ||
            !strncmp(line, "END read-blacklist", 3) ||
            !strncmp(line, "END write-blacklist", 3) ||
            !strncmp(line, "END connect-blacklist", 3) ||
            !strncmp(line, "END getaddrinfo-blacklist", 3)) {
            state = NoneID;
            continue;
        }
        blacklists[state] = new_blacklist(line, blacklists[state]);
    }
    fclose(file);
}

static FILE *my_fopen(const char *__restrict filename,
                      const char *__restrict modes)
{
    FILE *file = NULL;
    char *realname;
    struct stat path_stat;
    if (lstat(filename, &path_stat) == -1)
        realname = strdup(filename);
    else if ((path_stat.st_mode & S_IFMT) == S_IFLNK)
        realname = realpath(filename, NULL);
    else
        realname = strdup(filename);

    if (!realname)
        perror("realpath()");
    for (str_list_t *head = blacklists[OpenID]; head; head = head->next) {
        // printf("%s match %s\n", realname, head->value);
        if (!fnmatch(head->value, realname, FNM_FILE_NAME | FNM_PERIOD)) {
            errno = EACCES;
            goto fopen_logging;
        }
    }
    file = fopen(filename, modes);
    if (file)
        new_file(file, filename);
fopen_logging:
    if (realname)
        free(realname);
    char *_fn = strf(filename);
    char *_m = strf(modes);
    char *_fp = pointerf(file);
    dprintf(logger_fd, "[logger] fopen(%s, %s) = %s\n", _fn, _m, _fp);
    free(_fn);
    free(_m);
    free(_fp);
    return file;
}

static ssize_t my_fread(void *__restrict __ptr,
                        size_t __size,
                        size_t __n,
                        FILE *__restrict __stream)
{
    ssize_t ret = fread(__ptr, __size, __n, __stream);
    char *content = NULL;
    if (!ret)
        goto fread_logging;
    content = malloc(2 * ret * __size + 1);
    memcpy(content, __ptr, ret * __size);
    content[ret * __size] = 0;
    // ((char *) __ptr)[ret * __size] = 0;
    for (str_list_t *head = blacklists[ReadID]; head; head = head->next) {
        if (strstr(content, head->value)) {
            fseek(__stream, -ret * __size, SEEK_CUR);
            errno = EACCES;
            ret = 0;
            ((char *) __ptr)[0] = 0;
            goto fread_logging;
        }
    }
    char *_fn = pure_fn(get_filename(__stream));
    char *log_name = smprintf("./%d-%s-read.log", getpid(), _fn);
    free(_fn);
    int log_fd = open(log_name, O_WRONLY | O_CREAT, 0666);
    free(log_name);
    /*int shift = 0;
    for (int i = 0; i < ret * __size; ++i) {
        if (((char *) __ptr)[i] == '\n'){
            ++shift;
            content[i + shift - 1] = '\\';
            content[i + shift] = 'n';
        }
        else
            content[i + shift] = ((char *) __ptr)[i];
    }
    content[ret * __size + shift] = 0;*/
    /*for (int i = 0; i < ret * __size; ++i){
        content[i] = ((char *) __ptr)[i];
    }
    content[ret * __size] = 0;*/
    
    dprintf(log_fd, "%s\n", content);
    close(log_fd);
fread_logging:
    if (content)
        free(content);
    char *_p = pointerf(__ptr);
    char *_s = pointerf(__stream);
    dprintf(logger_fd, "[logger] fread(%s, %lu, %lu, %s) = %ld\n", _p, __size,
            __n, _s, ret);
    free(_p);
    free(_s);
    return ret;
}

static ssize_t my_fwrite(const void *__restrict __ptr,
                         size_t __size,
                         size_t __n,
                         FILE *__restrict __s)
{
    char *filename = get_filename(__s);
    ssize_t ret = 0;
    for (str_list_t *head = blacklists[WriteID]; head; head = head->next) {
        if (!fnmatch(head->value, filename, FNM_FILE_NAME | FNM_PERIOD)) {
            errno = EACCES;
            goto fwrite_logging;
        }
    }
    ret = fwrite(__ptr, __size, __n, __s);
    char *content = malloc(ret * __size + 1);
    int shift = 0;
    for (int i = 0; i < ret * __size; ++i) {
        if (((char *) __ptr)[i] == '\n'){
            ++shift;
            content[i + shift - 1] = '\\';
            content[i + shift] = 'n';
        }
        else
            content[i + shift] = ((char *) __ptr)[i];
    }
    content[ret * __size + shift] = 0;

    char *_fn = pure_fn(get_filename(__s));
    char *log_name = smprintf("./%d-%s-write.log", getpid(), _fn);
    free(_fn);
    int log_fd = open(log_name, O_WRONLY | O_CREAT, 0666);
    free(log_name);
    dprintf(log_fd, "%s\n", content);
    free(content);
    close(log_fd);
fwrite_logging:
    char *_p = strf(__ptr);
    char *_s = pointerf(__s);
    dprintf(logger_fd, "[logger] fwrite(%s, %lu, %lu, %s) = %ld\n", _p, __size,
            __n, _s, ret);
    free(_p);
    free(_s);
    return ret;
}

static int my_connect(int sockfd,
                      const struct sockaddr *addr,
                      socklen_t addrlen)
{
    char *ip = inet_ntoa(((struct sockaddr_in *) addr)->sin_addr);
    int ret = -1;
    for (str_list_t *head = blacklists[ConnectID]; head; head = head->next) {
        if (!strcmp(head->value, ip)) {
            errno = ECONNREFUSED;
            goto connect_logging;
        }
    }

    ret = connect(sockfd, addr, addrlen);
connect_logging:
    char *_ip = strf(ip);
    dprintf(logger_fd, "[logger] connect(%d, %s, %u) = %d\n", sockfd, _ip,
            addrlen, ret);
    free(_ip);
    return ret;
}

static int my_getaddrinfo(const char *restrict node,
                          const char *restrict service,
                          const struct addrinfo *restrict hints,
                          struct addrinfo **restrict res)
{
    int ret = EAI_NONAME;
    for (str_list_t *head = blacklists[GetaddrinfoID]; head;
         head = head->next) {
        if (!strcmp(head->value, node)) {
            goto connect_logging;
        }
    }

    ret = getaddrinfo(node, service, hints, res);
connect_logging:
    char *_n = strf(node);
    char *_s = strf(service);
    char *_h = pointerf(hints);
    char *_r = pointerf(res);
    dprintf(logger_fd, "[logger] getaddrinfo(%s, %s, %s, %s) = %d\n", _n, _s,
            _h, _r, ret);
    free(_n);
    free(_s);
    free(_h);
    free(_r);
    return ret;
}

static int my_system(const char *command)
{
    int ret = system(command);
    char *_c = strf(command);
    dprintf(logger_fd, "[logger] system(%s) = %d\n", _c, ret);
    free(_c);
    return ret;
}