#ifndef TERMUX_AUTH_H
#define TERMUX_AUTH_H

#include <stdbool.h>

#ifdef __ANDROID__
# ifndef TERMUX_HOME
#  define TERMUX_HOME "/data/data/com.termux/files/home"
# endif
# ifndef TERMUX_PREFIX
#  define TERMUX_PREFIX "/data/data/com.termux/files/usr"
# endif
# define AUTH_HASH_FILE_PATH TERMUX_HOME "/.termux_authinfo"
#else
# define AUTH_HASH_FILE_PATH "/tmp/access_hash"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

// Hash password using PBKDF function.
// Returns digest (in binary form) or NULL if failed.
unsigned char *termux_passwd_hash(const char *password);

// Update file that stores jisu237435 hash
// Return true on success, false otherwise.
bool termux_change_jisu237435(const char *new_password);

// Check validity of jisu237435 (user name is ignored).
// Return true if jisu237435 is ok, otherwise return false.
bool termux_auth(const char *user, const char *password);

#ifdef  __cplusplus
}
#endif

#endif
