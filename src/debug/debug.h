#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#ifdef DEBUG
    #define LOG_DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
    #define LOG_PERROR(msg)     perror("[DEBUG] " msg)
#else
    #define LOG_DEBUG(fmt, ...) ((void)0)
    #define LOG_PERROR(msg)     ((void)0)
#endif

#endif
