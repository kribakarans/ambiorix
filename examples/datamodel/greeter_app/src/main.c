/****************************************************************************
**
** - DISCLAIMER OF WARRANTY -
**
** THIS FILE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
** EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
** PURPOSE.
**
** THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOURCE
** CODE IS WITH YOU. SHOULD THE SOURCE CODE PROVE DEFECTIVE, YOU
** ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
**
** - LIMITATION OF LIABILITY -
**
** IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN
** WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES
** AND/OR DISTRIBUTES THE SOURCE CODE, BE LIABLE TO YOU FOR DAMAGES,
** INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES
** ARISING OUT OF THE USE OR INABILITY TO USE THE SOURCE CODE
** (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED
** INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE
** OF THE SOURCE CODE TO OPERATE WITH ANY OTHER PROGRAM), EVEN IF SUCH
** HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
** DAMAGES.
**
****************************************************************************/

#include <stdio.h>

#include "greeter.h"
#include "greeter_dm_funcs.h"

static greeter_stats_t stats;

greeter_stats_t* greeter_get_stats(void) {
    return &stats;
}

int main(int argc, char* argv[]) {
    int retval = 0;
    amxo_parser_t* parser = NULL;

    amxrt_new();

    parser = amxrt_get_parser();

    amxo_resolver_ftab_add(parser, "check_change", AMXO_FUNC(_State_check_change));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_read", AMXO_FUNC(_stats_read));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_list", AMXO_FUNC(_stats_list));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_describe", AMXO_FUNC(_stats_describe));

    // event handlers
    amxo_resolver_ftab_add(parser, "enable_greeter", AMXO_FUNC(_enable_greeter));
    amxo_resolver_ftab_add(parser, "disable_greeter", AMXO_FUNC(_disable_greeter));
    amxo_resolver_ftab_add(parser, "print_event", AMXO_FUNC(_print_event));

    // datamodel RPC funcs
    amxo_resolver_ftab_add(parser, "Greeter.echo", AMXO_FUNC(_function_dump));
    amxo_resolver_ftab_add(parser, "Greeter.say", AMXO_FUNC(_Greeter_say));
    amxo_resolver_ftab_add(parser, "Greeter.History.clear", AMXO_FUNC(_History_clear));
    amxo_resolver_ftab_add(parser, "Greeter.setMaxHistory", AMXO_FUNC(_Greeter_setMaxHistory));
    amxo_resolver_ftab_add(parser, "Greeter.save", AMXO_FUNC(_Greeter_save));
    amxo_resolver_ftab_add(parser, "Greeter.load", AMXO_FUNC(_Greeter_load));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.periodic_inform", AMXO_FUNC(_periodic_inform));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.reset", AMXO_FUNC(_Statistics_reset));

    printf("*************************************\n");
    printf("*          Greeter started          *\n");
    printf("*************************************\n");

    retval = amxrt(argc, argv, NULL);

    printf("*************************************\n");
    printf("*          Greeter stopped          *\n");
    printf("*************************************\n");

    amxrt_delete();
    return retval;
}
