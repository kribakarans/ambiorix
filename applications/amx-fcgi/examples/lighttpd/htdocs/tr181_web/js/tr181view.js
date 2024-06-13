(function (tr181view, $, undefined) {
    async function add_config_switches() {
        let set_check = false;
        let switch_button = await window.window.templates.load("switch");

        $('#CONFIG').append(switch_button.format('HTTP', 'Show HTTP Request/Response', ''));
        $('#CONFIG').append(switch_button.format('FOLLOW-TYPING', ' Fetch objects while typing', ''));
        $('#CONFIG').append(switch_button.format('FETCH', 'Fetch object after successfull SET/ADD/DELETE', ''));
        $('#CONFIG').append(switch_button.format('ANIMATION', 'Turn on animation', ''));
        $('#CONFIG').append(switch_button.format('BATCH', 'Run in batch', ''));

        set_check = document.get_cookie('HTTP', "true");
        $('#HTTP input').prop('checked', set_check);

        set_check = document.get_cookie('FOLLOW-TYPING', "false");
        $('#FOLLOW-TYPING input').prop('checked', set_check);

        set_check = document.get_cookie('FETCH', "false");
        $('#FETCH input').prop('checked', set_check);

        set_check = document.get_cookie('ANIMATION', "false");
        $('#ANIMATION input').prop('checked', set_check);

        set_check = document.get_cookie('BATCH', "false");
        $('#BATCH input').prop('checked', set_check);

        $('#BATCH input').click(function() {
            if (tr181view.input.is_checked('BATCH')) {
                $('#PARAMS').find('button[btn-action="submit"').hide();
                $('#RUNBATCH').show();
                $('#HTTP input').prop('checked', true);
            } else {
                $('#PARAMS').find('button[btn-action="submit"').show();
                $('#RUNBATCH').hide();
            }
        });

        $('#CONFIG input').click(function() {
            document.set_cookie($(this).parent().attr('id'), $(this).is(':checked'));
        });

        if (tr181view.input.is_checked('BATCH')) {
            $('#RUNBATCH').show();
            $('#HTTP input').prop('checked', true);
        } else {
            $('#RUNBATCH').hide();
        }
    }

    async function build_page() {
        let sidenav = await window.window.templates.load("side-nav");
        let resultview = await window.window.templates.load("result-view");
        let user = { user: "admin" }

        tr181model.open_session("admin", "admin");
        
        $('body .content').append(sidenav.format(user.user));
        $('body .content').append(resultview);
        
        add_config_switches();

        $('.sidenav').height($(window).height());  
    }

    function toggle_sidenav() {
        let sidenav = $('#SIDENAV');
        let dataview = $('#DATA-VIEW');
        let toggle = $(this);
        if (sidenav.is(":visible")) {
            tr181view.animate(sidenav, "slideOutLeft").then((element) => {
                sidenav.hide();
                dataview.toggleClass('offset-4 col-sm-8 col-sm-12');
                toggle.toggleClass('fa-angle-double-left fa-angle-double-right');
            });
        } else {
            sidenav.show();
            dataview.toggleClass('offset-4 col-sm-8 col-sm-12');
            tr181view.animate(sidenav, "slideInLeft").then((element) => {
                toggle.toggleClass('fa-angle-double-left fa-angle-double-right');
            });
        }
    }

    tr181view.init = async function() {        
        let fetch_html = [
            { name: "switch", uri: "/tr181_web/templates/switch.html" },
            { name: "side-nav", uri: "/tr181_web/templates/sidenav.html" },
            { name: "result-view", uri: "/tr181_web/templates/resultview.html" },
            { name: "result-obj-card", uri: "/tr181_web/templates/result-obj-card.html" },
            { name: "result-obj-param", uri: "/tr181_web/templates/result-obj-param.html" },
            { name: "result-header", uri: "/tr181_web/templates/result-header.html" },
            { name: "result-error", uri: "/tr181_web/templates/result-error.html" },
            { name: "result-message", uri: "/tr181_web/templates/result-message.html" },
            { name: "result-http-request", uri: "/tr181_web/templates/result-http-request-card.html" },
            { name: "result-http-response", uri: "/tr181_web/templates/result-http-response-card.html" },
            { name: "result-event", uri: "/tr181_web/templates/result-http-event-card.html" },
            { name: "request-card", uri: "/tr181_web/templates/request-card.html" },
            { name: "request-card-body-param", uri: "/tr181_web/templates/request-card-body-param.html" },
            { name: "request-card-body-cmd", uri: "/tr181_web/templates/request-card-body-cmd.html" },
            { name: "request-card-sub-body", uri: "/tr181_web/templates/request-card-sub-body.html" },
            { name: "request-card-event-id", uri: "/tr181_web/templates/request-card-event-id.html" },
            { name: "request-card-param", uri: "/tr181_web/templates/request-card-param.html" },
        ];

        window.window.templates.set(fetch_html);
        await build_page();
        window.window.templates.fetch();

        $('#EXEC').click(tr181ctrl.input.path_action);
        $('#RUNBATCH').click(tr181ctrl.input.handle_batch);
        $('#PATH').enterKey(tr181ctrl.input.path_action);
        $('#PATH').keypress(tr181ctrl.input.path_keypress);
        $('#ACTION').parent().find('.dropdown-item').click(tr181ctrl.input.action_changed);
        $('#LOGOUT').click(tr181ctrl.logout);
        $('#TOGGLE').click(toggle_sidenav);
        tr181view.input.update_action("GET");
    }

    tr181view.clear = function() {
        $('body .content').empty();
    }

    tr181view.animate = (element, animation, prefix = 'animate__') =>
        // We create a Promise and return it
        new Promise((resolve, reject) => {
            if (tr181view.input.is_checked('ANIMATION')) {
                const animationName = `${prefix}${animation}`;
                const node = element;

                element.addClass([ `${prefix}animated`, animationName ]);

                // When the animation ends, we clean the classes and resolve the Promise
                function handleAnimationEnd(event) {
                    event.stopPropagation();
                    element.removeClass([ `${prefix}animated`, animationName]);
                    resolve(element);
                }

                element.one('animationend', handleAnimationEnd);
            } else {
                resolve(element);
            }
        });

}(window.tr181view = window.tr181view || {}, jQuery ));