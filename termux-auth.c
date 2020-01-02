//
// Password authentication utilities for Termux
// Copyright (C) 2018-2020 Leonid Plyushch <leonid.plyushch@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.
//

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "termux-auth.h"

static void erase_ptr(void *ptr, unsigned int len) {
    volatile char *p = ptr;

    if (ptr == NULL) {
        return;
    }

    while (len--) {
        *p++ = 0x0;
    }
}

// Hash password using PBKDF function.
// Returns digest (in binary form) or NULL if failed.
unsigned char *termux_passwd_hash(const char *password) {
    const unsigned char *salt = (const unsigned char *) "Termux!";
    unsigned char *pbkdf_digest;

    if ((pbkdf_digest = (unsigned char *) malloc(SHA_DIGEST_LENGTH * sizeof(unsigned char))) == NULL) {
        fprintf(stderr, "%s(): failed to allocate memory.\n", __func__);
        return NULL;
    }

    if (!PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt,
        strlen((const char *)salt), 65536, SHA_DIGEST_LENGTH, pbkdf_digest)) {
        return NULL;
    }

    return pbkdf_digest;
}

// Update file that stores password hash
// Return true on success, false otherwise.
bool termux_change_passwd(const char *new_password) {
    FILE *termux_auth_file;
    bool is_password_changed = false;

    unsigned char *hashed_password = termux_passwd_hash(new_password);
    if (!hashed_password) {
        return false;
    }

    if ((termux_auth_file = fopen(AUTH_HASH_FILE_PATH, "w")) != NULL) {
        int n = fwrite(hashed_password, sizeof(unsigned char), SHA_DIGEST_LENGTH, termux_auth_file);
        fflush(termux_auth_file);
        fclose(termux_auth_file);

        erase_ptr(hashed_password, n);

        if (n == SHA_DIGEST_LENGTH) {
            is_password_changed = true;
        } else {
            fprintf(stderr, "%s(): password hash is truncated.\n", __func__);
        }
    }

    free(hashed_password);

    return is_password_changed;
}

// Check validity of password (user name is ignored).
// Return true if password is ok, otherwise return false.
bool termux_auth(const char *user, const char *password) {
    FILE *termux_auth_file;
    unsigned char *auth_info;
    unsigned char *hashed_password;
    bool is_authenticated = false;

    if ((auth_info = (unsigned char *)malloc(SHA_DIGEST_LENGTH * sizeof(unsigned char))) == NULL) {
        fprintf(stderr, "%s(): failed to allocate memory.\n", __func__);
        return false;
    }

    if ((hashed_password = termux_passwd_hash(password)) == NULL) {
        free(auth_info);
        return false;
    }

    if ((termux_auth_file = fopen(AUTH_HASH_FILE_PATH, "rb")) != NULL) {
        int n = fread(auth_info, sizeof(unsigned char), SHA_DIGEST_LENGTH, termux_auth_file);
        fclose(termux_auth_file);

        if (n == SHA_DIGEST_LENGTH) {
            if (memcmp(auth_info, hashed_password, SHA_DIGEST_LENGTH) == 0) {
                is_authenticated = true;
            }
        } else {
            fprintf(stderr, "%s(): password hash is truncated.\n", __func__);
        }
    }

    erase_ptr(auth_info, SHA_DIGEST_LENGTH);
    erase_ptr(hashed_password, SHA_DIGEST_LENGTH);
    free(auth_info);
    free(hashed_password);

    return is_authenticated;
}
