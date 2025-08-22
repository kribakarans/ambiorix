/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/
%define api.pure full
%locations
%defines
%define parse.error verbose
%parse-param {void *ctx}
%lex-param {void *ctx}

%{
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <amxc/amxc.h>

#include "amxp_expr_priv.h"
#include "amxp_expr.tab.h"

%}


%union
{
  amxp_expr_node_t* node;
  int64_t integer;
  amxp_txt_t cptr;
  bool boolean;
  amxc_var_t *ptrval;
  amxp_expr_comp_t comp;
  amxc_string_t *ptrstr;
}

%token <cptr>    MULTILINECOMMENT
%token <node>    EOF_TOKEN
%token <cptr>    STRING
%token <cptr>    TEXT
%token <cptr>    FIELD
%token <boolean> BOOL
%token <integer> DIGIT

%token <comp> COMPERATOR

%type <node> stream expr conditional_expr logical_or_expr logical_and_expr 
%type <node> primary value list_values
%type <ptrstr>  path
%type <cptr>    function_header

%left LAND LOR LNOT

%{
    int yylex(YYSTYPE* lvalp, YYLTYPE* llocp, void * yyscanner);
    void yyerror(YYLTYPE* locp, void* scanner, const char* err);
    void yywarning(YYLTYPE* locp, void* scanner, const char* err);
    amxp_expr_t *yyget_extra ( void * yyscanner );

    void yyerror(YYLTYPE* locp, void* scanner, const char* err) {
        amxp_expr_t *context = (amxp_expr_t *)yyget_extra(scanner);
        amxp_expr_printf("ERROR (%s@%d) - %s\n", 
                         err,
                         locp->first_line,
                         amxc_string_get(&context->msg, 0));
        amxc_string_clean(&context->msg);
    }

    void yywarning(YYLTYPE* locp, void* scanner, const char* err) {
        amxp_expr_t *context = (amxp_expr_t *)yyget_extra(scanner);
        amxp_expr_printf("WARNING (%s@%d) - %s\n",
                         err, 
                         locp->first_line,
                         amxc_string_get(&context->msg, 0));
        amxc_string_clean(&context->msg);
    }

    #define scanner x->scanner
    #define parser_ctx ((amxp_expr_t *)yyget_extra(ctx))
    #define NOOP

%}

%start stream

%%

stream
  : expr ';' { 
      $$ = $1; 
    }
  | EOF_TOKEN { $$ = NULL; }
  ;

expr: /* empty */ { 
          amxp_expr_node_t* node = NULL;
          amxc_var_t* value = NULL;
          amxp_expr_node_new(&node, amxp_expr_value);
          amxc_var_new(&value);
          amxc_var_set(bool, value, true);
          amxp_expr_node_set_value(node, value);
          amxp_expr_node_push(&parser_ctx->nodes, node);
          $$ = node;
      }
    | conditional_expr
    ;

conditional_expr
    : logical_or_expr
    ;

logical_or_expr
    : logical_and_expr
    | logical_or_expr LOR logical_and_expr  { 
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_or);
        amxp_expr_node_set_left(node, $1);
        amxp_expr_node_set_right(node, $3);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    ;

logical_and_expr
    : primary
    | logical_and_expr LAND primary { 
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_and);
        amxp_expr_node_set_left(node, $1);
        amxp_expr_node_set_right(node, $3);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    ;

primary
    : '(' expr ')' {
        $$ = $2;
      }
    | LNOT primary {
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_not);
        amxp_expr_node_set_left(node, $2);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | value 
    | value primary {
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_and);
        amxp_expr_node_set_left(node, $1);
        amxp_expr_node_set_right(node, $2);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | value COMPERATOR value {
        amxp_expr_node_t* node = NULL;    
        amxp_expr_node_new(&node, amxp_expr_compare_oper);
        amxp_expr_node_set_compop(node, $2);
        amxp_expr_node_set_left(node, $1);
        amxp_expr_node_set_right(node, $3);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | function_header '(' list_values ')' {
        amxp_expr_node_t* node = NULL;    
        amxp_expr_node_new(&node, amxp_expr_bool_func);
        amxp_expr_node_set_function(node, strdup($1.txt));
        amxc_llist_for_each(it, &$3->right.args) {
          amxp_expr_node_t* arg = amxc_container_of(it, amxp_expr_node_t, it);
          amxp_expr_node_add_value(node, arg);
        }
        amxp_expr_node_delete(&$3);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    ;

value
    : TEXT { 
        amxc_var_t* value = NULL;
        amxp_expr_node_t* node = NULL;
        amxc_string_t txt;

        $1.txt[$1.length] = 0;
        amxc_string_init(&txt, 0);
        amxc_string_push_buffer(&txt, $1.txt, $1.length + 1);
        amxc_string_trim(&txt, NULL);
        amxc_var_new(&value); 
        amxp_expr_node_new(&node, amxp_expr_value);
        amxc_var_set(cstring_t, value, amxc_string_take_buffer(&txt));
        amxp_expr_node_set_value(node, value);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | DIGIT { 
        amxc_var_t* value = NULL;
        amxp_expr_node_t* node = NULL;
        amxc_var_new(&value); 
        amxp_expr_node_new(&node, amxp_expr_value);
        amxc_var_set(int64_t, value, $1);
        amxp_expr_node_set_value(node, value);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | BOOL { 
        amxc_var_t* value = NULL;
        amxp_expr_node_t* node = NULL;
        amxc_var_new(&value); 
        amxp_expr_node_new(&node, amxp_expr_value);
        amxc_var_set(bool, value, $1);
        amxp_expr_node_set_value(node, value);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | path {
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_field);
        amxp_expr_node_set_field(node, amxc_string_take_buffer($1));
        $$ = node;
        amxp_expr_node_push(&parser_ctx->nodes, node);
        amxc_string_delete(&$1);
      }
    | '[' list_values ']' {
        amxp_expr_node_get_value(parser_ctx, $2);
        $$ = $2;
      }
    | function_header '(' list_values ')' {
        amxp_expr_node_t* node = NULL;    
        amxp_expr_node_new(&node, amxp_expr_value_func);
        amxp_expr_node_set_function(node, strdup($1.txt));
        amxc_llist_for_each(it, &$3->right.args) {
          amxp_expr_node_t* arg = amxc_container_of(it, amxp_expr_node_t, it);
          amxp_expr_node_add_value(node, arg);
        }
        amxp_expr_node_delete(&$3);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    ;

function_header
    : STRING {
        $1.txt[$1.length] = 0;
        $$ = $1;
      }
    ;

list_values
    : {
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_value);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    | list_values ',' value {
        amxp_expr_node_add_value($1, $3);
        $$ = $1;
      }
    | value {
        amxp_expr_node_t* node = NULL;
        amxp_expr_node_new(&node, amxp_expr_value);
        amxp_expr_node_add_value(node, $1);
        amxp_expr_node_push(&parser_ctx->nodes, node);
        $$ = node;
      }
    ;

path
  : path '.' STRING  {
      $3.txt[$3.length] = 0;
      amxc_string_appendf($1, ".%s", $3.txt);
    }
  | path '.' DIGIT {
      amxc_string_appendf($1, ".%" PRId64, $3);
    }
  | STRING {
      amxc_string_new(&$$,0);
      $1.txt[$1.length] = 0;
      amxc_string_appendf($$, "%s", $1.txt);
    }
  | '.' STRING {
      amxc_string_new(&$$,0);
      $2.txt[$2.length] = 0;
      amxc_string_appendf($$, ".%s", $2.txt);
    }
  | '.' DIGIT {
      amxc_string_new(&$$,0);
      amxc_string_appendf($$, ".%" PRId64, $2);
    }
  | FIELD {
      amxc_string_new(&$$,0);
      $1.txt[$1.length] = 0;
      amxc_string_appendf($$, "%s", $1.txt);
    }
  ;

%%
