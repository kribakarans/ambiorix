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

#include "amxc/amxc_hash.h"

unsigned int amxc_RS_hash(const char* str, const unsigned int len) {
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = hash * a + (*str);
        a = a * b;
    }

    return hash;
}

unsigned int amxc_JS_hash(const char* str, const unsigned int len) {
    unsigned int hash = 1315423911;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash ^= ((hash << 5) + (*str) + (hash >> 2));
    }

    return hash;
}

unsigned int amxc_PJW_hash(const char* str, const unsigned int len) {
    const unsigned int BitsInUnsignedInt = (unsigned int) (sizeof(unsigned int) * 8);
    const unsigned int ThreeQuarters = (unsigned int) ((BitsInUnsignedInt * 3) / 4);
    const unsigned int OneEighth = (unsigned int) (BitsInUnsignedInt / 8);
    const unsigned int HighBits = (unsigned int) (0xFFFFFFFF) << (BitsInUnsignedInt - OneEighth);
    unsigned int hash = 0;
    unsigned int test = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = (hash << OneEighth) + (*str);

        if((test = hash & HighBits) != 0) {
            hash = (( hash ^ (test >> ThreeQuarters)) & (~HighBits));
        }
    }

    return hash;
}

unsigned int amxc_ELF_hash(const char* str, const unsigned int len) {
    unsigned int hash = 0;
    unsigned int x = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = (hash << 4) + (*str);
        if((x = hash & 0xF0000000L) != 0) {
            hash ^= (x >> 24);
        }
        hash &= ~x;
    }

    return hash;
}

unsigned int amxc_BKDR_hash(const char* str, const unsigned int len) {
    unsigned int seed = 131; /* 31 131 1313 13131 131313 etc.. */
    unsigned int hash = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = (hash * seed) + (*str);
    }

    return hash;
}

unsigned int amxc_SDBM_hash(const char* str, const unsigned int len) {
    unsigned int hash = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = (*str) + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

unsigned int amxc_DJB_hash(const char* str, const unsigned int len) {
    unsigned int hash = 5381;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = ((hash << 5) + hash) + (*str);
    }

    return hash;
}

unsigned int amxc_DEK_hash(const char* str, const unsigned int len) {
    unsigned int hash = len;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
    }
    return hash;
}

unsigned int amxc_BP_hash(const char* str, const unsigned int len) {
    unsigned int hash = 0;
    unsigned int i = 0;
    for(i = 0; i < len; str++, i++) {
        hash = hash << 7 ^ (*str);
    }

    return hash;
}

unsigned int amxc_FNV_hash(const char* str, const unsigned int len) {
    const unsigned int fnv_prime = 0x811C9DC5;
    unsigned int hash = 0;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash *= fnv_prime;
        hash ^= (int) (*str);
    }

    return hash;
}

unsigned int amxc_AP_hash(const char* str, const unsigned int len) {
    unsigned int hash = 0xAAAAAAAA;
    unsigned int i = 0;

    for(i = 0; i < len; str++, i++) {
        hash ^= ((i & 1) == 0) ? ((hash << 7) ^ (*str) * (hash >> 3)) :
        (~((hash << 11) + ((*str) ^ (hash >> 5))));
    }

    return hash;
}
