#include "library.h"
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BE_LOG_FILE "/var/log/brute_log.txt"
#define BE_DELAY 700

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char    *username,
            *password,
            *protocol,
            *hostname;

    pam_get_item(pamh, PAM_USER, (void*)&username);
    pam_get_item(pamh, PAM_AUTHTOK, (void*)&password);
    pam_get_item(pamh, PAM_SERVICE, (void*)&protocol);
    pam_get_item(pamh, PAM_RHOST, (void*)&hostname);

    // Added a delay to ensure that BruteExpose gets to read the entry.
    // In terms of practicality, I should have wrote the entire program in C,
    // but I am not familiar with the language.
    usleep(BE_DELAY);
    FILE *fd = fopen(BE_LOG_FILE, "a");

    if (fd != NULL) {
        fprintf(fd, "%s %s %s %s \n", username, password, hostname, protocol);
        fclose(fd);
    }

    return PAM_SUCCESS;
}

