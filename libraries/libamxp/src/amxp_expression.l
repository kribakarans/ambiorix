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
%option reentrant bison-bridge
%option never-interactive
%option nounput
%option noinput
%option noyywrap
%option bison-locations

%{
    #ifndef _GNU_SOURCE
    #define _GNU_SOURCE
    #endif
    #include <string.h>
    #include <sys/types.h>
    #include <dlfcn.h>
    #include <stdint.h>
    #include <amxc/amxc.h>

    #include "amxp_expr_priv.h"
    #include "amxp_expr.tab.h"

    #if __SIZE_WIDTH__ == 64
    #define ssize_t_abs(x) labs(x)
    #else
    #define ssize_t_abs(x) abs(x)
    #endif
   
    #define YY_EXTRA_TYPE amxp_expr_t*
    #define YY_INPUT(buf,result,max_size) { \
      ssize_t read_result = 0; \
      read_result = yyextra->reader(yyextra, buf, max_size); \
      if (read_result == -1) { \
        YY_FATAL_ERROR( "input in flex scanner failed" ); \
      } \
      result = read_result > 0? ssize_t_abs(read_result):0; \
    }

    extern int yylex \
               (YYSTYPE * yylval_param ,  YYLTYPE* yylloc_param, yyscan_t yyscanner);

    #define UNUSED __attribute__((unused))
    #define YY_DECL int yylex \
               (YYSTYPE * yylval_param , UNUSED YYLTYPE* yylloc_param, yyscan_t yyscanner)
%}

%x MULTI_LINE_COMMENT SINGLE_LINE_COMMENT LONG_TEXT LONG_TEXT_SQ FIELD_PATH

NEWLINE  \r?\n

%%

"/*"                                   { BEGIN( MULTI_LINE_COMMENT ); }
<MULTI_LINE_COMMENT>{
    "*"                { yymore(); }
    [^*\n]+            { yymore(); }
    [^*\n]*{NEWLINE}   { yymore(); }
    "*/"               { yylval->cptr.txt = yytext;
                         yylval->cptr.length = yyleng - 2;
                         BEGIN(INITIAL);
                       }
}
                                       
"//"                                   { BEGIN( SINGLE_LINE_COMMENT ); }
<SINGLE_LINE_COMMENT>{NEWLINE}         { BEGIN(INITIAL); }
<SINGLE_LINE_COMMENT>"*"               { }
<SINGLE_LINE_COMMENT>[^*\n]+           { }

"'"                                    { BEGIN(LONG_TEXT_SQ); }
<LONG_TEXT_SQ>{
    "*"              { yymore(); }
    {NEWLINE}        { yymore(); }
    [^\\']+          { yymore(); }
    [\\].            { yymore(); }
    "'"              { yylval->cptr.txt = yytext;
                       yylval->cptr.length = yyleng - 1;
                       BEGIN(INITIAL);
                       return TEXT;
                     }
    .                { yymore(); }
}


"\""                                   { BEGIN(LONG_TEXT); }
<LONG_TEXT>{
    "*"              { yymore(); }
    {NEWLINE}        { yymore(); }
    [^\\"]+          { yymore(); }
    [\\].            { yymore(); }
    "\""             { yylval->cptr.txt = yytext;
                       yylval->cptr.length = yyleng - 1;
                       BEGIN(INITIAL);
                       return TEXT;
                     }
    .                { yymore(); }
}

"{"                                    { BEGIN(FIELD_PATH); }
<FIELD_PATH>{
    "*"              { yymore(); }
    "}"              { yylval->cptr.txt = yytext;
                       yylval->cptr.length = yyleng - 1;
                       BEGIN(INITIAL);
                       return FIELD;
                     }
    .                { yymore(); }
}

[ \t]                     { }
[\n]                      { }

<<EOF>>                   { yylval->integer = token_eof;
                            yyterminate();
                            return EOF_TOKEN; 
                          }

"!"                       { return LNOT; }
not                       { return LNOT; }
"&&"                      { return LAND; }
and                       { return LAND; }
"||"                      { return LOR; }
or                        { return LOR; }

"=="                      { yylval->comp = amxp_expr_comp_equal;
                            return COMPERATOR; 
                          }
"!="                      { yylval->comp = amxp_expr_comp_not_equal;
                            return COMPERATOR; 
                          }
"<"                       { yylval->comp = amxp_expr_comp_lesser;
                            return COMPERATOR; 
                          }
">"                       { yylval->comp = amxp_expr_comp_bigger;
                            return COMPERATOR; 
                          }
"<="                      { yylval->comp = amxp_expr_comp_lesser_equal;
                            return COMPERATOR;
                          }
">="                      { yylval->comp = amxp_expr_comp_bigger_equal;
                            return COMPERATOR; 
                          }
matches                   { yylval->comp = amxp_expr_comp_matches;
                            return COMPERATOR; 
                          }
starts[ \t]{1,}with       { yylval->comp = amxp_expr_comp_starts_with;
                            return COMPERATOR; 
                          }
ends[ \t]{1,}with         { yylval->comp = amxp_expr_comp_ends_with;
                            return COMPERATOR; 
                          }
in                        { yylval->comp = amxp_expr_comp_in;
                            return COMPERATOR;
                          }
"~="                      { yylval->comp = amxp_expr_comp_contains;
                            return COMPERATOR;
                          }
"^="                      { yylval->comp = amxp_expr_comp_equals_ignorecase;
                            return COMPERATOR;
                          }
(?i:true)                 { yylval->boolean = true;
                            return BOOL;
                          }
(?i:false)                { yylval->boolean = false;
                            return BOOL;
                          }

[[:digit:]]+              { char *endptr = NULL;
                            yylval->integer = strtoll(yytext, &endptr, 0);
                            return DIGIT; 
                          }
-[[:digit:]]+             { char *endptr = NULL;
                            yylval->integer = strtoll(yytext, &endptr, 0);
                            return DIGIT; 
                          }

[a-zA-Z0-9\-_@]+          { yylval->cptr.txt = yytext;
                            yylval->cptr.length = yyleng;
                            return STRING;
                          }

\n|.                      { return yytext[0]; }

%%

void amxp_expr_create_lex(amxp_expr_t *expr) {
	yylex_init(&expr->scanner);
    yyset_extra(expr, expr->scanner);
}

void amxp_expr_destroy_lex(amxp_expr_t *expr) {
	yylex_destroy(expr->scanner);
}
