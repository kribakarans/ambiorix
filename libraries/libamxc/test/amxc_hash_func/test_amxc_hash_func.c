/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
**
** Redistribution and use in source and binary forms, with or without modification,
** are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright notice,
** this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above copyright notice,
** this list of conditions and the following disclaimer in the documentation
** and/or other materials provided with the distribution.
**
** Subject to the terms and conditions of this license, each copyright holder
** and contributor hereby grants to those receiving rights under this license
** a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
** (except for failure to satisfy the conditions of this license) patent license
** to make, have made, use, offer to sell, sell, import, and otherwise transfer
** this software, where such license applies only to those patent claims, already
** acquired or hereafter acquired, licensable by such copyright holder or contributor
** that are necessarily infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright holders and
** non-copyrightable additions of contributors, in source or binary form) alone;
** or
**
** (b) combination of their Contribution(s) with the work of authorship to which
** such Contribution(s) was added by such copyright holder or contributor, if,
** at the time the Contribution is added, such addition causes such combination
** to be necessarily infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any copyright
** holder or contributor is granted under this license, whether expressly, by
** implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
** USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <amxc/amxc_hash.h>

#include "test_amxc_hash_func.h"

#include <amxc/amxc_macros.h>
static void generate_string(char* str, size_t length) {
    const char* base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t len = strlen(base);
    for(unsigned int i = 0; i < length; i++) {
        str[i] = base[rand() % len];
    }
}

void amxc_hash_generation_check(UNUSED void** state) {
    char* key[] = { "abcdefghijklmnopqrstuvwxyz1234567890",
        "0987654321zyxwvutsrqponmlkjihgfedcba",
        "Damien",
        "Tom",
        "Peter",
        "Project Ambiorix",
        "1234567890",
        "abcdefghijklmnopqrstuvwxyz",
        "!@#$%^&*()_",
        "1+1=2",
        NULL};

    for(int i = 0; key[i]; i++) {
        printf("Key:                         %s\n", key[i]);
        printf(" 1. RS-Hash Function Value:   %u\n", amxc_RS_hash(key[i], strlen(key[i])));
        printf(" 2. JS-Hash Function Value:   %u\n", amxc_JS_hash(key[i], strlen(key[i])));
        printf(" 3. PJW-Hash Function Value:  %u\n", amxc_PJW_hash(key[i], strlen(key[i])));
        printf(" 4. ELF-Hash Function Value:  %u\n", amxc_ELF_hash(key[i], strlen(key[i])));
        printf(" 5. BKDR-Hash Function Value: %u\n", amxc_BKDR_hash(key[i], strlen(key[i])));
        printf(" 6. SDBM-Hash Function Value: %u\n", amxc_SDBM_hash(key[i], strlen(key[i])));
        printf(" 7. DJB-Hash Function Value:  %u\n", amxc_DJB_hash(key[i], strlen(key[i])));
        printf(" 8. DEK-Hash Function Value:  %u\n", amxc_DEK_hash(key[i], strlen(key[i])));
        printf(" 9. BP-Hash Function Value:   %u\n", amxc_BP_hash(key[i], strlen(key[i])));
        printf("10. FNV-Hash Function Value:  %u\n", amxc_FNV_hash(key[i], strlen(key[i])));
        printf("11. AP-Hash Function Value:   %u\n", amxc_AP_hash(key[i], strlen(key[i])));
    }
}

static unsigned int array[2006];
static bool first_double = false;

static int amxc_hash_distribution_setup() {
    memset(array, 0, sizeof(array));
    srand(2013);
    first_double = false;
    printf("\n===========================================\n");

    return 0;
}

static int amxc_hash_distribution_teardown() {
    unsigned int empty_buckets = 0;
    unsigned int unique_buckets = 0;
    unsigned int max_chain_length = 0;
    unsigned int number_of_chains = 0;
    unsigned int total_chain_lengths = 0;
    for(int i = 0; i < 2006; i++) {
        if(array[i] == 0) {
            empty_buckets++;
        }
        if(array[i] > max_chain_length) {
            max_chain_length = array[i];
        }
        if(array[i] > 1) {
            number_of_chains++;
            total_chain_lengths += array[i];
        }
        if(array[i] == 1) {
            unique_buckets++;
        }
    }
    printf("Nr. of empty buckets   = %d\n", empty_buckets);
    printf("Nr. of chained buckets = %d\n", number_of_chains);
    printf("Nr. of uinque buckets  = %d\n", unique_buckets);
    printf("Total buckets          = %d\n", empty_buckets + number_of_chains + unique_buckets);
    printf("max chain length       = %d\n", max_chain_length);
    printf("average chain length   = %f\n", (double) (total_chain_lengths / number_of_chains));
    printf("===========================================\n");

    return 0;
}

void amxc_hash_distibution_RS_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("RS hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_RS_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_JS_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("JS hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_JS_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_PJW_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("PJW hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_PJW_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_ELF_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("ELF hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_ELF_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_BKDR_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("BKDR hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_BKDR_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_SBDM_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("SBDM hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_SDBM_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_DJB_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("DJB hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_DJB_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_DEK_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("DEK hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_DEK_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_BP_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("BP hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_BP_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_FNV_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("FNV hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_FNV_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_distibution_AP_check(UNUSED void** state) {
    amxc_hash_distribution_setup();
    printf("AP hash algorithm\n");

    for(int i = 0; i < 2006; i++) {
        char key[15];
        generate_string(key, 15);
        unsigned int hash = amxc_AP_hash(key, 15) % 2006;
        if(array[hash] && !first_double) {
            first_double = true;
            printf("First double insertion = %d\n", i);
        }
        array[hash]++;
    }
    amxc_hash_distribution_teardown();
}

void amxc_hash_BKDR_hashes_check(UNUSED void** state) {
    printf("[Key1] = %d\n", amxc_BKDR_hash("Key1", 4) % 64);
    printf("[Key2] = %d\n", amxc_BKDR_hash("Key2", 4) % 64);
    printf("[Key3] = %d\n", amxc_BKDR_hash("Key3", 4) % 64);
    printf("[Key4] = %d\n", amxc_BKDR_hash("Key4", 4) % 64);
    printf("[Key5] = %d\n", amxc_BKDR_hash("Key5", 4) % 64);
    printf("[Key6] = %d\n", amxc_BKDR_hash("Key6", 4) % 64);
    printf("[Key7] = %d\n", amxc_BKDR_hash("Key7", 4) % 64);
    printf("[Key8] = %d\n", amxc_BKDR_hash("Key8", 4) % 64);
    printf("[Key9] = %d\n", amxc_BKDR_hash("Key9", 4) % 64);
    printf("[Key11] = %d\n", amxc_BKDR_hash("Key11", 5) % 64);
    printf("[Key21] = %d\n", amxc_BKDR_hash("Key21", 5) % 64);
    printf("[Key31] = %d\n", amxc_BKDR_hash("Key31", 5) % 64);
    printf("[Key41] = %d\n", amxc_BKDR_hash("Key41", 5) % 64);
    printf("[Key51] = %d\n", amxc_BKDR_hash("Key51", 5) % 64);
    printf("[Key61] = %d\n", amxc_BKDR_hash("Key61", 5) % 64);
    printf("[Key71] = %d\n", amxc_BKDR_hash("Key71", 5) % 64);
    printf("[Key81] = %d\n", amxc_BKDR_hash("Key81", 5) % 64);
    printf("[Key91] = %d\n", amxc_BKDR_hash("Key91", 5) % 64);
    printf("[Key110] = %d\n", amxc_BKDR_hash("Key110", 6) % 64);
    printf("[Key210] = %d\n", amxc_BKDR_hash("Key210", 6) % 64);
    printf("[Key310] = %d\n", amxc_BKDR_hash("Key310", 6) % 64);
    printf("[Key410] = %d\n", amxc_BKDR_hash("Key410", 6) % 64);
    printf("[Key510] = %d\n", amxc_BKDR_hash("Key510", 6) % 64);
    printf("[Key610] = %d\n", amxc_BKDR_hash("Key610", 6) % 64);
    printf("[Key710] = %d\n", amxc_BKDR_hash("Key710", 6) % 64);
    printf("[Key810] = %d\n", amxc_BKDR_hash("Key810", 6) % 64);
    printf("[Key910] = %d\n", amxc_BKDR_hash("Key910", 6) % 64);
}
