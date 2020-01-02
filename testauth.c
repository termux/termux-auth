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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "termux-auth.h"

// PoC of 'password login'

int main(void) {
    char *password;

    password = getpass("Password: ");
    if (!password) {
        puts("Failed to read password input.");
        return EXIT_FAILURE;
    }

    if (termux_auth("termux", password)) {
        puts("Password is OK");
    } else {
        puts("Invalid password.");
    }
}
