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

#if !defined(__AMXC_HASH_H__)
#define __AMXC_HASH_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>

/**
   @file
   @brief
   Ambiorix string hash functions header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_hash Hash functions
 */

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   A simple hash function from Robert Sedgwicks Algorithms in C book.
   TODO: What happens if str is NULL?

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_RS_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   A bitwise hash function written by Justin Sobel
   TODO: What happens if str is NULL?

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_JS_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string

   This hash algorithm is based on work by Peter J. Weinberger of AT&T Bell Labs.
   The book Compilers (Principles, Techniques and Tools) by Aho, Sethi and Ulman,
   recommends the use of hash functions that employ the hashing methodology
   found in this particular algorithm.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_PJW_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   Similar to the PJW Hash function, but tweaked for 32-bit processors.
   Its the hash function widely used on most UNIX systems.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_ELF_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   This hash function comes from Brian Kernighan and Dennis Ritchie's book
   "The C Programming Language".
   It is a simple hash function using a strange set of possible seeds which all
   constitute a pattern of 31....31...31 etc,
   it seems to be very similar to the DJB hash function.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_BKDR_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   This is the algorithm of choice which is used in the open source SDBM project.
   The hash function seems to have a good over-all distribution for many
   different data sets. It seems to work well in situations where there is a
   high variance in the MSBs of the elements in a data set.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_SDBM_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   An algorithm produced by Professor Daniel J. Bernstein and shown first to the
   world on the usenet newsgroup comp.lang.c. It is one of the most efficient
   hash functions ever published.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_DJB_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   A simple hash function from Robert Sedgwicks Algorithms in C book.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_DEK_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   An algorithm proposed by Donald E. Knuth in The Art Of Computer Programming
   Volume 3, under the topic of sorting and search chapter 6.4.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_BP_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   A simple hash function from Robert Sedgwicks Algorithms in C book.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_FNV_hash(const char* str, const unsigned int len);

/**
   @ingroup amxc_hash
   @brief
   Calculate a hash from a string.

   An algorithm produced by Arash Partow.
   He took ideas from all of the above hash functions making a hybrid rotative
   and additive hash function algorithm.
   There isn't any real mathematical analysis explaining why one should use this
   hash function instead of the others described above other than the fact that
   I tried to resemble the design as close as possible to a simple LFSR.
   An empirical result which demonstrated the distributive abilities of the hash
   algorithm was obtained using a hash-table with 100003 buckets, hashing The
   Project Gutenberg Etext of Webster's Unabridged Dictionary, the longest
   encountered chain length was 7, the average chain length was 2,
   the number of empty buckets was 4579.

   @param str a string that needs to be hashed
   @param len the length that must be used of the string to calculate the hash

   @return
   The calculated hash value
 */
unsigned int amxc_AP_hash(const char* str, const unsigned int len);

#ifdef __cplusplus
}
#endif

#endif // __AMXC_HASH_H__
