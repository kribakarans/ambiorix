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

#ifndef __TEST_AMXC_HTABLE_H__
#define __TEST_AMXC_HTABLE_H__

void amxc_htable_new_delete_null_check(void** state);
void amxc_htable_new_delete_check(void** state);
void amxc_htable_delete_func_check(void** state);
void amxc_htable_init_clean_null_check(void** state);
void amxc_htable_init_clean_check(void** state);
void amxc_htable_init_reserve_check(void** state);
void amxc_htable_set_hash_func_check(void** state);
void amxc_htable_key2index_null_check(void** state);
void amxc_htable_key2index_check(void** state);
void amxc_htable_insert_null_check(void** state);
void amxc_htable_insert_check(void** state);
void amxc_htable_insert_same_key_check(void** state);
void amxc_htable_insert_same_it_check(void** state);
void amxc_htable_insert_grow_check(void** state);
void amxc_htable_insert_grow_big_check(void** state);
void amxc_htable_is_empty_null_check(void** state);
void amxc_htable_is_empty_check(void** state);
void amxc_htable_size_null_check(void** state);
void amxc_htable_size_check(void** state);
void amxc_htable_capacity_null_check(void** state);
void amxc_htable_capacity_check(void** state);
void amxc_htable_get_null_check(void** state);
void amxc_htable_get_check(void** state);
void amxc_htable_get_chained_check(void** state);
void amxc_htable_get_first_null_check(void** state);
void amxc_htable_get_first_check(void** state);
void amxc_htable_get_last_null_check(void** state);
void amxc_htable_get_last_check(void** state);
void amxc_htable_take_null_check(void** state);
void amxc_htable_take_check(void** state);
void amxc_htable_take_chained_check(void** state);
void amxc_htable_take_first_null_check(void** state);
void amxc_htable_take_first_check(void** state);
void amxc_htable_contains_null_check(void** state);
void amxc_htable_contains_check(void** state);
void amxc_htable_it_get_next_null_check(void** state);
void amxc_htable_it_get_next_check(void** state);
void amxc_htable_it_get_next_chained_check(void** state);
void amxc_htable_it_get_next_key_null_check(void** state);
void amxc_htable_it_get_next_key_check(void** state);
void amxc_htable_it_get_previous_null_check(void** state);
void amxc_htable_it_get_previous_check(void** state);
void amxc_htable_it_get_previous_chained_check(void** state);
void amxc_htable_it_get_previous_key_null_check(void** state);
void amxc_htable_it_get_previous_key_check(void** state);
void amxc_htable_it_take_null_check(void** state);
void amxc_htable_it_take_check(void** state);
void amxc_htable_it_take_chained_check(void** state);
void amxc_htable_it_get_key_check(void** state);
void amxc_htable_it_init_null_check(void** state);
void amxc_htable_it_clean_null_check(void** state);
void amxc_htable_it_clean_func_check(void** state);
void amxc_htable_get_sorted_keys_check(void** state);
void amxc_htable_move_check(void** state);
void amxc_htable_check_null_ptr(void** state);

#endif //__TEST_AMXC_HTABLE_H__