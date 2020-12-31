#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <string.h>
#include "utils.h"

extern unsigned log__level;

// Log levels
#define LVL(_)  \
    _(DBG)      \
    _(INFO)     \
    _(CRIT)

// log to stderr by default
#define OUT stderr

#ifdef BUILD_DEBUG
#define ENTRY debug("ENTERING %s()", __func__)
#define TEE_DEFAULT_LOG_LEVEL LOG_DBG
#define LOG(LVL, ...)                                              \
    do {                                                           \
        if (log__level <= (LVL)) {                                 \
            (void) fprintf(OUT, "%s:%d ", __func__, __LINE__);     \
            (void) fprintf(OUT, __VA_ARGS__);                      \
            (void) fprintf(OUT, "\n");                             \
            fflush(OUT);                                           \
        }                                                          \
    } while (0)
#define debug(...) LOG(LOG_DBG, __VA_ARGS__)
#define info(...) LOG(LOG_INFO, __VA_ARGS__)
#define crit(...) LOG(LOG_CRIT, __VA_ARGS__)
#else
#define ENTRY
#define TEE_DEFAULT_LOG_LEVEL LOG_CRIT
#define LOG(LVL, ...)
#define debug(...)
#define info(...)
#define crit(...)
#endif

#define NOP(x) (void)(x)

// define log levels
enum {
#define DEFINE(_1) GLUE(LOG_, _1),
    LVL(DEFINE) LOG_MAX,
#undef DEFINE
};

// sets logging level for the library
void log_level(unsigned lvl);
// read level from environment
int get_env_log_level(unsigned *lvl);

#endif /* LOG_H */
