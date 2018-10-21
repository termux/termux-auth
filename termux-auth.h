#ifndef TERMUX_AUTH_H
#define TERMUX_AUTH_H

#include <stdbool.h>

#ifdef __ANDROID__
# define AUTH_HASH_FILE_PATH "/data/data/com.termux/files/home/.termux_authinfo"
#else
# define AUTH_HASH_FILE_PATH "/tmp/access_hash"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

// Hash password using PBKDF function.
// Returns digest (in binary form) or NULL if failed.
unsigned char *termux_passwd_hash(const char *password);

// Update file that stores password hash
// Return true on success, false otherwise.
bool termux_change_passwd(const char *new_password);

// Check validity of password (user name is ignored).
// Return true if password is ok, otherwise return false.
bool termux_auth(const char *user, const char *password);

#ifdef  __cplusplus
}
#endif

#endif
