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

#include "amxb_pcb.h"


int amxb_pcb_to_pcb_var_list(const amxc_llist_t* source,
                             variant_list_t* dest) {

    amxc_llist_for_each(it, source) {
        amxc_var_t* var_source = amxc_var_from_llist_it(it);
        variant_list_iterator_t* pcb_vit = variant_list_iterator_create(NULL);
        variant_t* var_dest = variant_list_iterator_data(pcb_vit);
        variant_list_append(dest, pcb_vit);
        amxb_pcb_to_pcb_var(var_source, var_dest);
    }

    return 0;
}

int amxb_pcb_to_pcb_var_map(const amxc_htable_t* source,
                            variant_map_t* dest) {
    amxc_htable_for_each(it, source) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_t* var_source = amxc_var_from_htable_it(it);
        variant_map_iterator_t* pcb_vit = variant_map_iterator_create(key, NULL);
        variant_t* var_dest = variant_map_iterator_data(pcb_vit);
        variant_map_append(dest, pcb_vit);
        amxb_pcb_to_pcb_var(var_source, var_dest);
    }

    return 0;
}

int amxb_pcb_to_pcb_var(const amxc_var_t* source,
                        variant_t* dest) {
    switch(amxc_var_type_of(source)) {
    case AMXC_VAR_ID_BOOL: {
        variant_setBool(dest, amxc_var_constcast(bool, source));
    }
    break;

    case AMXC_VAR_ID_INT8: {
        variant_setInt8(dest, amxc_var_constcast(int8_t, source));
    }
    break;

    case AMXC_VAR_ID_UINT8: {
        variant_setUInt8(dest, amxc_var_constcast(uint8_t, source));
    }
    break;

    case AMXC_VAR_ID_INT16: {
        variant_setInt16(dest, amxc_var_constcast(int16_t, source));
    }
    break;

    case AMXC_VAR_ID_UINT16: {
        variant_setUInt16(dest, amxc_var_constcast(uint16_t, source));
    }
    break;

    case AMXC_VAR_ID_INT32: {
        variant_setInt32(dest, amxc_var_constcast(int32_t, source));
    }
    break;

    case AMXC_VAR_ID_UINT32: {
        variant_setUInt32(dest, amxc_var_constcast(uint32_t, source));
    }
    break;

    case AMXC_VAR_ID_INT64: {
        variant_setInt64(dest, amxc_var_constcast(int64_t, source));
    }
    break;

    case AMXC_VAR_ID_UINT64: {
        variant_setUInt64(dest, amxc_var_constcast(uint64_t, source));
    }
    break;

    case AMXC_VAR_ID_FD: {
        variant_setFd(dest, amxc_var_constcast(fd_t, source));
    }
    break;

    case AMXC_VAR_ID_HTABLE: {
        const amxc_htable_t* table = amxc_var_constcast(amxc_htable_t, source);
        variant_map_t* var_map = NULL;
        variant_initialize(dest, variant_type_map);
        var_map = variant_da_map(dest);
        amxb_pcb_to_pcb_var_map(table, var_map);
    }
    break;

    case AMXC_VAR_ID_LIST: {
        const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, source);
        variant_list_t* var_list = NULL;
        variant_initialize(dest, variant_type_array);
        var_list = variant_da_list(dest);
        amxb_pcb_to_pcb_var_list(list, var_list);
    }
    break;

    case AMXC_VAR_ID_TIMESTAMP: {
        struct tm tm;
        const amxc_ts_t* ts = amxc_var_constcast(amxc_ts_t, source);
        amxc_ts_to_tm_utc(ts, &tm);
        variant_setDateTime(dest, &tm);
    }
    break;

    default: {
        char* string = amxc_var_dyncast(cstring_t, source);
        variant_setChar(dest, string);
        free(string);
    }
    break;
    }

    return 0;
}

int amxb_pcb_from_pcb_var_map(variant_map_t* source,
                              amxc_var_t* dest) {
    variant_map_iterator_t* it = NULL;
    variant_map_for_each(it, source) {
        const char* key = variant_map_iterator_key(it);
        variant_t* var_source = variant_map_iterator_data(it);
        amxc_var_t* var_dest = amxc_var_add_new_key(dest, key);
        if(var_dest != NULL) {
            amxb_pcb_from_pcb_var(var_source, var_dest);
        }
    }

    return 0;
}

int amxb_pcb_from_pcb_var_list(variant_list_t* source,
                               amxc_var_t* dest) {
    variant_list_iterator_t* it = NULL;
    variant_list_for_each(it, source) {
        variant_t* var_source = variant_list_iterator_data(it);
        amxc_var_t* var_dest = amxc_var_add_new(dest);
        amxb_pcb_from_pcb_var(var_source, var_dest);
    }

    return 0;
}

int amxb_pcb_from_pcb_var(const variant_t* source,
                          amxc_var_t* dest) {
    switch(variant_type(source)) {
    case variant_type_bool: {
        amxc_var_set(bool, dest, variant_bool(source));
    }
    break;

    case variant_type_int8:
        amxc_var_set(int8_t, dest, variant_int8(source));
        break;
    case variant_type_int16:
        amxc_var_set(int16_t, dest, variant_int16(source));
        break;

    case variant_type_int32:
        amxc_var_set(int32_t, dest, variant_int32(source));
        break;

    case variant_type_int64:
        amxc_var_set(int64_t, dest, variant_int64(source));
        break;

    case variant_type_uint8:
        amxc_var_set(uint8_t, dest, variant_uint8(source));
        break;

    case variant_type_uint16:
        amxc_var_set(uint16_t, dest, variant_uint16(source));
        break;

    case variant_type_uint32:
        amxc_var_set(uint32_t, dest, variant_uint32(source));
        break;

    case variant_type_uint64:
        amxc_var_set(uint64_t, dest, variant_uint64(source));
        break;

    case variant_type_file_descriptor:
        amxc_var_set(fd_t, dest, variant_fd(source));
        break;

    case variant_type_map: {
        variant_map_t* var_map = variant_da_map(source);
        amxc_var_set_type(dest, AMXC_VAR_ID_HTABLE);
        amxb_pcb_from_pcb_var_map(var_map, dest);
    }
    break;

    case variant_type_array: {
        variant_list_t* var_list = variant_da_list(source);
        amxc_var_set_type(dest, AMXC_VAR_ID_LIST);
        amxb_pcb_from_pcb_var_list(var_list, dest);
    }
    break;

    case variant_type_date_time: {
        amxc_ts_t ts;
        char* date_time = variant_char(source);
        amxc_ts_parse(&ts, date_time, strlen(date_time));
        amxc_var_set(amxc_ts_t, dest, &ts);
        free(date_time);
    }
    break;

    default: {
        char* string = variant_char(source);
        amxc_var_set(cstring_t, dest, string);
        free(string);
    }
    break;
    }

    return 0;
}

int amxb_var_type_from_pcb_arg_type(const uint32_t arg_type) {
    int ret_type = arg_type;

    switch(arg_type) {
    case argument_type_byte_array:
    case argument_type_unknown:
        ret_type = AMXC_VAR_ID_NULL;
        break;
    case argument_type_string:
        ret_type = AMXC_VAR_ID_CSTRING;
        break;
    case argument_type_int8:
        ret_type = AMXC_VAR_ID_INT8;
        break;
    case argument_type_int16:
        ret_type = AMXC_VAR_ID_INT16;
        break;
    case argument_type_int32:
        ret_type = AMXC_VAR_ID_INT32;
        break;
    case argument_type_int64:
        ret_type = AMXC_VAR_ID_INT64;
        break;
    case argument_type_uint8:
        ret_type = AMXC_VAR_ID_UINT8;
        break;
    case argument_type_uint16:
        ret_type = AMXC_VAR_ID_UINT16;
        break;
    case argument_type_uint32:
        ret_type = AMXC_VAR_ID_UINT32;
        break;
    case argument_type_uint64:
        ret_type = AMXC_VAR_ID_UINT64;
        break;
    case argument_type_bool:
        ret_type = AMXC_VAR_ID_BOOL;
        break;
    case argument_type_list:
        ret_type = AMXC_VAR_ID_LIST;
        break;
    case argument_type_date_time:
        ret_type = AMXC_VAR_ID_TIMESTAMP;
        break;
    case argument_type_file_descriptor:
        ret_type = AMXC_VAR_ID_FD;
        break;
    case argument_type_variant:
        ret_type = AMXC_VAR_ID_ANY;
        break;
    case argument_type_double:
        ret_type = AMXC_VAR_ID_DOUBLE;
        break;
    default:
        ret_type = AMXC_VAR_ID_HTABLE;
        break;
    }

    return ret_type;
}