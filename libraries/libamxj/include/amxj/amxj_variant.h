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

#if !defined(__VARIANT_JSON_H__)
#define __VARIANT_JSON_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <unistd.h>

#ifndef __YAJL_GEN_H__
#error "Missing include <yajl/yajl_gen.h>"
#endif

#ifndef __AMXC_VARIANT_TYPE_H__
#error "Missing include <amxc/amxc_variant_type.h>"
#endif

/**
   @file
   @brief
   JSON String Ambiorix variant implementation
 */

/**
   @defgroup amxj Ambiorix JSON string variant

   JSON (JavaScript Object Notation) is an open standard file format and data interchange format
   that uses human-readable text to store and transmit data objects consisting of attribute–value
   pairs and arrays (or other serializable values). It is a common data format with diverse uses
   in electronic data interchange, including that of web applications with servers.

   JSON is a language-independent data format. It was derived from JavaScript, but many modern
   programming languages include code to generate and parse JSON-format data. JSON filenames
   use the extension .json.

   This ambiorix library provides JSON parsing and JSON generation features.
   Any Ambiorix variant can be converted to a JSON string and any valid JSON string can be converted
   to an ambiorix variant.

   The Ambiorix JSON variant is using [yajl](https://lloyd.github.io/yajl/) to parse and generate
   JSON strings.

   JSON strings can be read from asynchronous I/O (like a socket) and the full string doesn't have to be
   available at once. The JSON reader keeps track of the current state.

   Besides providing functions to read a JSON string from a file descriptor and writing a JSON string
   to a file descriptor from a variant this library also adds a new variant type on top of the
   standard variant types provided by libamxc. This makes it possible to use the amxc variant API with
   JSON strings.

   Example - Setting a JSON string in a variant
   @code
   void main(void) {
       amxc_var_t data;

       amxc_var_init(&data);
       amxc_var_set(jstring_t, &data, "[1,2,3]"); // variant containing a string with valid JSON
       amxc_var_dump(&data, STDOUT_FILENO);

       amxc_var_cast(&data, AMXC_VAR_ANY); // automatically converts to a variant containing a list.
       amxc_var_dump(&data, STDOUT_FILENO);

       amxc_var_clean(&data);
   }
   @endcode

   In the above example amxc_var_set will fail if the provided string is not a valid JSON string.
 */

/**
   @ingroup amxj
   @defgroup amxj_reader Ambiorix JSON string reader
 */

/**
   @ingroup amxj
   @defgroup amxj_writer Ambiorix JSON string writer
 */

/**
   @ingroup amxj_reader

   @brief
   Defines the states of a JSON reader.
 */
typedef enum _amxj_reader_state_t {
    amxj_reader_start = 0,     /**< Initial state.*/
    amxj_reader_start_verify,  /**< Used when converting a JSON string to a specific type,
                                    a check is performed to see if the types are matching*/
    amxj_reader_parsing,       /**< JSON reader is currently parsing a JSON string.*/
    amxj_reader_done,          /**< Parsing of the JSON string is done.*/
    amxj_reader_fail           /**< The parsing of the JSON string is done, but failed (invalid JSON)*/
} amxj_reader_state_t;

/**
   @ingroup amxj

   @brief
   Defines the variant type name for variants containing a valid JSON string.
 */
#define AMXC_VAR_NAME_JSON "jstring_t"

/**
   @ingroup amxj

   @brief
   Returns the JSON string variant type identifier.
 */
#define AMXC_VAR_ID_JSON amxc_var_get_type_id_from_name(AMXC_VAR_NAME_JSON)

/**
   @ingroup amxj

   @brief
   Internal data structure to keep track of JSON string parsing and generation.
 */
typedef struct _variant_json_t variant_json_t;

/**
   @ingroup amxj_reader

   @brief
   Creates and initializes yajl generator.

   Creates and initializes a yajl json generator opaque handle. This handle can be used
   when calling yajl api directly.

   @param jvar a (json string) ambiorix variant

   @return
   an opaque json gnerator handle or NULL when failed to create or initialize it.
 */
yajl_gen amxj_get_json_gen(const amxc_var_t* const jvar);

/**
   @ingroup amxj_reader

   @brief
   Creates a new JSON reader.

   A JSON reader is used to parse a JSON string and create an ambiorix variant that matches
   the description in the read JSON string.

   The created reader can be passed to @ref amxj_read which will read the string from
   a file descriptor (socket). The current state of the reader can be queried using
   @ref amxj_reader_get_state. When the full JSON string is parsed the resulting variant
   can be fetched using @ref amxj_reader_result.

   When the reader is not needed anymore call @ref amxj_reader_delete to free the
   allocated memory.

   @param reader a pointer where the address of the new allocated reader can be stored.

   @return
   0 when successfully created a json reader, any other value indicates an error occurred.
 */
int amxj_reader_new(variant_json_t** reader);

/**
   @ingroup amxj_reader

   @brief
   Reads from a file descriptor and parses the read content as JSON.

   Reads as much as possible from the file descriptor and parses the read data as
   JSON. If the read data is not valid data, the function will fail.

   If all recieved data is still valid data, but the JSON string is still not complete
   and currently no more data is available on the file descriptor this function will return
   0 and the state of the reader (@ref amxj_reader_get_state) will be amxj_reader_parsing

   Example
   @code
   int main(int argc, char* argv[]) {
     int fd = -1;
     variant_json_t* reader = NULL;
     amxc_var_t* data = NULL;

     if (argc < 1) {
        printf("No file name provied");
        exit(0);
     }

     if (amxj_reader_new(&reader) != 0) {
        printf("Failed to create json file reader");
        exit(1);
    }

     fd = open(argv[1], O_RDONLY);
     if(fd == -1) {
        printf("File open failed %s - error 0x%8.8X", argv[1], errno);
        exit(2);
     }

     if (amxj_read(reader, fd) < 0) {
        printf("Read failed from %s - error 0x%8.8X", argv[1], errno);
        exit(3);
     }

     data = amxj_reader_result(reader);
     amxj_reader_delete(&reader);
     close(fd);

     amxc_var_dump(&data, STDOUT_FILENO);

     amxc_var_delete(&data);

     return 0;
   }
   @endcode

   @param reader a pointer to previously allocated reader.
   @param fd a file descriptor, used to read

   @return
   Number of bytes read. If 0 check the state of the reader it can be done
   (amxj_reader_done or amxj_reader_fail), or needs more data (amxj_reader_parsing).
   When < 0 an read error occured.
 */
ssize_t amxj_read(variant_json_t* const reader, int fd);

/**
   @ingroup amxj_reader

   @brief
   Get the resulting variant of a JSON reader.

   The caller gets ownership of the returned variant. If the variant is not needed
   anymore it must be freed by calling amxc_var_delete

   @note
   Before calling this function make sure that parsing of the JSON string is done.
   Check the state of the reader by calling @ref amxj_reader_get_state.

   @param reader a pointer to previously allocated reader.

   @return
   Pointer to the resulting variant.
 */
amxc_var_t* amxj_reader_result(variant_json_t* const reader);

/**
   @ingroup amxj_reader

   @brief
   Returns the current state of the JSON reader.

   The current state of the reader is one of @ref amxj_reader_state_t values.

   When the state is amxj_reader_done the full JSON string has been parsed and the
   resulting variant can be retrieved using @ref amxj_reader_result.

   @param reader a pointer to previously allocated reader.

   @return
   The current reader state.
 */
amxj_reader_state_t amxj_reader_get_state(const variant_json_t* const reader);

/**
   @ingroup amxj_reader

   @brief
   Deletes a previously allocated JSON reader.

   Frees the memory allocated for the reader. If the resulting variant is needed
   fetch it before deleting the reader using @ref amxj_reader_result.

   This function will reset the pointer to NULL.

   @param reader a pointer to previously allocated reader.
 */
void amxj_reader_delete(variant_json_t** reader);

/**
   @ingroup amxj_writer

   @brief
   Creates a new JSON writer.

   A JSON writer is used to generate a JSON string from an amxc variant.

   The created writer can be passed to @ref amxj_write which will write the string to
   a file descriptor (socket).

   When the reader is not needed anymore call @ref amxj_writer_delete to free the
   allocated memory.

   @param writer a pointer where the address of the new allocated writer can be stored.
   @param var the amxc variant that needs to be written in JSON string format

   @return
   0 when successfully created a json writer, any other value indicates an error occurred.
 */
int amxj_writer_new(variant_json_t** writer, const amxc_var_t* const var);

/**
   @ingroup amxj_writer

   @brief
   Writes a JSON string to a file descriptor.

   Writes the content of the amxc variant, provided when creating the JSON writer using
   @ref amxj_writer_new, to the file descriptor as a JSON string.

   @param writer a pointer to previously allocated writer.
   @param fd the file descriptor where the JSON string needs to be written to.

   @return
   0 when successfully written the content of the variant as a JSON string to the file
   descriptor, any other value indicates an error occurred.
 */
ssize_t amxj_write(variant_json_t* const writer, int fd);

/**
   @ingroup amxj_writer

   @brief
   Deletes a previously allocated JSON writer.

   Frees the memory allocated for the writer.
   This function will reset the pointer to NULL.

   @param writer a pointer to previously allocated writer.
 */
void amxj_writer_delete(variant_json_t** writer);

/**
   @ingroup amxj
   @brief
   Conversion helper function for amxc variant

   See amxc_var_constcast in libamxc

   Will return NULL if the variant is not of a JSON string type

   @note
   Do not call this function directly, use libamxc macro amxc_var_constcast with the
   type argument `jstring_t`

   @note
   do not free the returned pointer.

   @param var pointer to a variant struct

   @return constant char pointer to the JSON string value or NULL if the
           variant is not of a JSON string type
 */
const char* amxc_var_get_const_jstring_t(const amxc_var_t* const var);

/**
   @ingroup amxj
   @brief
   Setter helper function

   See amxc_var_set in libamxc

   @note
   Do not call this function directly, use macro @ref amxc_var_set with the
   type argument `jstring_t`

   @note
   When the provided value is not a valid JSON string the set will fail.

   @param var pointer to a variant struct
   @param val the value to set, which must be a valid JSON string

   @return
   0 when the value was set, any other value indicates an error.
 */
int amxc_var_set_jstring_t(amxc_var_t* const var, const char* const val);


#ifdef __cplusplus
}
#endif

#endif // __VARIANT_JSON_H__
