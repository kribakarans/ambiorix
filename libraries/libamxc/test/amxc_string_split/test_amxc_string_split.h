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

#ifndef __TEST_AMXC_STRING_SPLIT_H__
#define __TEST_AMXC_STRING_SPLIT_H__

void test_can_split_string_using_separator(void** state);
void test_can_split_string_using_space_separators(void** state);
void test_check_parts_are_correct(void** state);

void test_can_split_csv_string_to_variant(void** state);
void test_split_csv_handles_sequence_of_commas_as_multiple_items(void** state);
void test_split_csv_string_handles_comma_in_quotes_correctly(void** state);
void test_split_csv_string_handles_empty_string_correctly(void** state);
void test_can_split_csv_string_with_multi_array_to_variant(void** state);
void test_can_split_csv_string_can_start_with_array_to_variant(void** state);
void test_can_split_csv_string_supports_multi_level_array_to_variant(void** state);
void test_can_split_csv_string_with_single_quotes_to_variant(void** state);
void test_can_split_csv_string_with_double_quotes_to_variant(void** state);
void test_split_csv_can_handle_empty_sublist(void** state);

void test_can_split_ssv_string_to_variant(void** state);
void test_split_ssv_handles_sequence_of_spaces_as_one_separator(void** state);
void test_split_ssv_string_handles_spaces_in_quotes_correctly(void** state);
void test_can_split_ssv_string_with_single_quotes_to_variant(void** state);
void test_split_ssv_string_handles_empty_string_correctly(void** state);
void test_can_split_ssv_string_with_multi_array_to_variant(void** state);

void test_split_word_checks_quotes(void** state);
void test_split_word_checks_curly_brackets(void** state);
void test_split_word_checks_square_brackets(void** state);
void test_split_word_checks_round_brackets(void** state);
void test_amxc_string_split_word(void** state);
void test_amxc_string_split_word_quotes2(void** state);
void test_amxc_string_split_word_can_start_with_punctuation(void** state);
void test_split_string_on_new_line(void** state);

void test_functions_validates_input_arguments(void** state);

#endif // __TEST_AMXC_STRING_H__