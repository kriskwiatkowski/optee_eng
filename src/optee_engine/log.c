#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/e_os2.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"
#include "utils.h"

/* engine will try to read TEE_ENG_DEBUG from the
 * environment to set a log level */
#define LOG_LEVEL_VAR "TEE_ENG_DEBUG"

/* stores current log level. logs with level
 * below log__level are discarded. */
unsigned log__level = LOG_MAX;

int get_env_log_level(unsigned *lvl) {
    int tmp;
    char *var = getenv(LOG_LEVEL_VAR);
    if (!var) {
        return TEE_R_GENERIC;
    }

    errno = 0;
    tmp = strtol(var, NULL, 3);
    if (errno || tmp < 0) {
        info("Wrong value of " LOG_LEVEL_VAR". Set value between 0 and 3.");
        return TEE_R_GENERIC;
    }
    *lvl = (unsigned)tmp;
    return TEE_R_SUCCESS;
}

// sets log level
void log_level(unsigned lvl) {
    if(lvl >= LOG_MAX) {
        // ensure this will be logged
        LOG(log__level,"Wrong value set for "LOG_LEVEL_VAR);
        return;
    }

    log__level = lvl;
}
