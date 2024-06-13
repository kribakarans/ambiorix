(function (tr181ui, $, undefined) {
    (function (input, $, undefined) {
        function find_card(path, method) {
            let encoded_path = btoa(path);
            let node = $('#PARAMS .card[dm-object="' + encoded_path + '"][action="' + method + '"]');
            if (node.length == 0) {
                return undefined;
            }
            return node;
        }

        input.action_color = {
            GET: '61affe',
            SET: '50e3c2',
            ADD: '49cc90',
            DELETE: 'f93e3e',
            CMD: '49cc90',
            SUB: '50e3c2',
            UPLOAD: 'F100FF',
            DOWNLOAD: '61affe',
        }

        input.action_icon = {
            GET: 'fa-caret-square-o-right',
            SET: 'fa-caret-square-o-right',
            ADD: 'fa-caret-square-o-right',
            DELETE: 'fa-caret-square-o-right',
            CMD: 'fa-caret-square-o-right',
            SUB: 'fa-caret-square-o-right',
            UPLOAD: 'fa-caret-square-o-right',
            DOWNLOAD: 'fa-caret-square-o-right',
        }
    
        input.clear = function() {
            $('#PATH').val('');
        }
    
        input.path = function() {
            let path = $('#PATH').val();
            return path;
        }

        input.filename = function() {
            let path = $('#FILENAME').val();
            return path;
        }

        input.file = function() {
            let file = $("#FILE")[0].files[0];
            return file;
        }

        input.add_card = function(path, method) {
            let node = find_card(path, method); 
            
            if (node == undefined) {
                let encoded_path =  btoa(path);
                node = $(window.templates.get("request-card").format(encoded_path, method, path));
                $('#PARAMS').append(node);
                if (method == "SET" || method == "ADD") {
                    body = $(window.templates.get("request-card-body-param"));
                    node.append(body);
                } else if (method == "CMD") {
                    body = $(window.templates.get("request-card-body-cmd"));
                    node.append(body);
                } else if (method == "SUB") {
                    let event_id = document.uuid();
                    node.find('button[btn-action="submit"').remove();
                    body = $(window.templates.get("request-card-sub-body").format(event_id));
                    node.append(body);
                    tr181view.input.set_card_event_id(node, event_id);
                } else {
                    node.find('button[btn-action="collapse"').remove();
                }
                if ((method != "GET" && method != "SUB") || typeof(EventSource) === "undefined") {
                    node.find('button[btn-action="start-watch"').remove();
                }
                if (tr181view.input.is_checked('BATCH')) {
                    node.find('button[btn-action="submit"').hide();
                }
                node.find('.card-header').css('background-color', '#' + tr181view.input.action_color[method]);
                node.find('button').click(function() {
                    tr181ctrl.input.handle_card_button(node, $(this));
                });
                tr181view.animate(node, 'backInLeft');
            }
            node.find('input').first().focus();            
            return node;
        }
        
        input.add_param = function(card) {
            let last_param = card.find('.input-group').last();
            let new_param = $(window.templates.get('request-card-param'));
            new_param.insertAfter(last_param);
            new_param.find('input').first().focus();
            new_param.find('button').click(function() {
                tr181ctrl.input.handle_card_button(card, $(this));
            });        
            return new_param;
        }

        input.remove_param = function(card, button) {
            if (card.find('.card-body .input-group').length == 1) {
                card.find('.card-body .input-group input').val('');
            } else {
                button.parent().remove();
            }
        }

        input.get_params = function(card) {
            let params = {};
            let param_name = '';
            card.find('input[type=text]').each(
                function(index) {
                    if ((index % 2) == 0) {
                        param_name = $(this).val();
                    } else {
                        try {
                            params[param_name] = JSON.parse($(this).val());
                        }
                        catch(err) {
                            params[param_name] = $(this).val();
                        }
                    }
                }
            );
            return params;
        }

        input.get_toggles = function(card) {
            let toggles = { };
            card.find('input[type=checkbox]').each(function(index) {
                toggles[$(this).attr('id')] = $(this).is(':checked');
            });
            return toggles;
        }

        input.get_card_path = function(card) {
            return card.find('[dm-object]').text();
        }

        input.set_card_event_id = function(card, id) {
            if (id) {
                card.attr('event-id', id);
            } else {
                card.removeAttr('event-id');
            }
        }

        input.show_event_id = function(card, event_id) {
            let node = $(window.templates.get('request-card-event-id').format(event_id));
            card.append(node);
            card.find('.collapse').collapse('show');
        }

        input.hide_event_id = function(card) {
            card.find('.collapse').remove();
        }

        input.get_card_event_id = function(card) {
            return card.attr('event-id');
        }

        input.get_card_filter = function(card) {
            return card.find('input[type=text]').first().val();
        }

        input.get_card_method = function(card) {
            return card.attr('action');
        }

        input.remove_cards = function(path) {
            $('#PARAMS .card[dm-object]').each(function() {
                let card = $(this);
                let card_path = $(this).attr('dm-object');
                if (card_path.startsWith(path)) {
                    tr181view.animate(card, 'hinge').then((element) => { 
                        let event_id = tr181view.input.get_card_event_id(card);
                        element.remove();
                        document.event_stream.unsubscribe();
                    });
                }
            });
        }

        input.get_cards = function() {
            return $('#PARAMS .card[dm-object]');
        }

        input.is_checked = function(id) {
            let node = $('#' + id).find('input');
            if (node.length != 0) {
                return node[0].checked;
            }
            return false;
        }

        input.set_focus = function() {
            $('#PATH').focus();
        }

        input.get_action = function() {
            return $('#ACTION').text();
        }

        input.update_action = function(action) {
            $('#EXEC').find('.fa').removeClass(tr181view.input.action_icon[action]);
            $('#EXEC').find('.fa').addClass(tr181view.input.action_icon[action]);
            $('#ACTION').text(action)
            $('#ACTION').css('background-color', '#' + tr181view.input.action_color[action]);
            if(action == "UPLOAD") {
                $('#PATH').hide();
                $('#FILE').show();
                $('#FILENAME').hide();
            } else if(action == "DOWNLOAD"){
                $('#PATH').hide();
                $('#FILE').hide();
                $('#FILENAME').show();
            } else {
                $('#PATH').show();
                $('#FILE').hide();
                $('#FILENAME').hide();
            }
        }

        input.collapse_card = function(card) {
            card.find('.collapse').collapse("toggle");
        }

        input.find_card = function(dm_path, action) {
            
            let query = '.card[dm-object="' + btoa(dm_path) + '"][action="' + action + '"]';
            let card = $('#PARAMS').find(query);
            return card;
        }

        input.card_find_param = function(card, param_name) {
            let found = false;
            let param = undefined;
            card.find('input').each(function(index) {
                if ((index % 2) == 0) {
                    if (param_name == $(this).val()) {
                        param = $(this).parent();
                    }
                }
            });

            return param;
        }

        input.set_watch_button = function(button, watch) {
            if (watch) {
                button.find('.fa').removeClass('fa-eye-slash');
                button.find('.fa').addClass('fa-eye');
                button.attr('btn-action', 'start-watch');

            } else {
                button.find('.fa').removeClass('fa-eye');
                button.find('.fa').addClass('fa-eye-slash');
                button.attr('btn-action', 'stop-watch');
            }
        }

    } (tr181view.input = tr181view.input || {}, jQuery ));
}(window.tr181view = window.tr181view || {}, jQuery ));