(function (tr181view, $, undefined) {
    (function (result, $, undefined) {
        // PRIVATE
        function add_http(type, method, uri, data) {
            let template_name = "result-http-response";
            let node_id = "#HTTP-RESPONSE-DATA";
            if (type == "request") {
                template_name = "result-http-request";
                node_id = "#HTTP-REQUEST-DATA";
            }
            let new_node = $(window.templates.get(template_name).format(method, uri));
            if (data == undefined) {
                new_node.find(node_id).remove();
            } else {
                new_node.find(node_id + ' pre').append(JSON.stringify(data, undefined, 2));
            }
            $('#RESULT').append(new_node);
        }

        let event_id = 0;

        function add_event(uri, event, data, type) {
            let template_name = "result-event";
            let new_node = $(window.templates.get(template_name).format(event_id, uri, event));
            new_node.find('#EVENT-DATA-' + event_id + ' pre').append('event-id = "' + type + '"\n\n');
            if (data != undefined) {
                new_node.find('#EVENT-DATA-' + event_id + ' pre').append(JSON.stringify(data, undefined, 2));
            }
            $('#RESULT').append(new_node);
            tr181view.animate(new_node, 'lightSpeedInRight');
            $('#EVENT-DATA-' + event_id).on("shown.bs.collapse", on_object_expand_done);
            //new_node.find('#EVENT-DATA-' + event_id).collapse('show');
            event_id = event_id + 1;
        }


        function add_object(path, index) {
            let new_node = $(window.templates.get("result-obj-card").format(path, index));
            let obj_node = $('#RESULT').append(new_node);
            let path_parts = path.split('.');
            path_parts.splice(-1);
            if (isNaN(path_parts.slice(-1))) {
                new_node.find('.btn-right-allign button[btn-action="delete"]').remove();
            }
            new_node.find('.btn-right-allign button').click(tr181ctrl.result.handle_header_button);
            return new_node.find('tbody')
        }

        function add_params(params, node) {
            let ordered_params = Object.keys(params).sort().reduce(
                (obj, key) => {
                  obj[key] = params[key];
                  return obj;
                },
                { }
            );
            for(let param in ordered_params) {
                if (ordered_params.hasOwnProperty(param)) {
                    node.append(window.templates.get("result-obj-param").format(param, ordered_params[param]));
                }
            }
        }

        function on_object_expand_done() {
            $(this).parent()[0].scrollIntoView({ behavior: 'smooth', block: 'start'});
        }

        // PUBLIC
        result.clear = function() {
            $("#RESULT").empty();
            $("#QUERY").empty();    
        }

        result.header = function(path) {
            if (!tr181view.input.is_checked('HTTP')) {
                $('#QUERY').empty();
                $('#QUERY').append(window.templates.get("result-header").format(path));
            }
        }

        result.message = function(msg) {
            if (!tr181view.input.is_checked('HTTP')) {
                $('#QUERY').empty();
                if (typeof msg == 'string') {
                    $('#QUERY').append(window.templates.get("result-message").format(msg));
                } else {
                    $('#QUERY').append(window.templates.get("result-message").format(msg.message));
                }
            }
        }

        result.error = function(err) {
            $('#QUERY').empty();
            if (typeof err == 'string') {
                $('#QUERY').append(window.templates.get("result-error").format(err));
            } else {
                $('#QUERY').append(window.templates.get("result-error").format(err.message));
            }
            tr181view.animate($('#QUERY'), 'rubberBand');
        }

        result.show_objects = function(data) {
            data.forEach((obj, index) => {
                let node = add_object(obj.path, index);
                if (obj.uniqueKeys) {
                    add_params(obj.uniqueKeys, node);
                }
                add_params(obj.parameters, node);
                index = index + 1
            })
    
            $('#RESULT .card .collapse').on("shown.bs.collapse", on_object_expand_done);
            $('#RESULT td button').click(tr181ctrl.result.on_set_clicked);
        }      

        result.show_http_request = function(method, path, data) {
            if (tr181view.input.is_checked('HTTP') || method == "CMD") {
                add_http("request", method, path, data);
            }
        }        

        result.show_http_response = function(method, path, data) {
            if (tr181view.input.is_checked('HTTP') || method == "CMD") {
                add_http("response", method, path, data);
            }
        }        

        result.show_event = function(path, event, data, event_id) {
            if (tr181view.input.is_checked('HTTP')) {
                add_event(path, event, data, event_id);
            } else {
                let card = tr181view.result.find_card(path);
                card.find('.collapse').collapse('show');
                if (data.parameters) {
                    for (const [name, value] of Object.entries(data.parameters)) {
                        card.find('td[dm="' + name + '"]').text(value);
                        tr181view.animate(card.find('td[dm="' + name + '"]'), 'heartBeat');
                    }
                }
            }
        }        

        result.open = function(path) {
            if (path == undefined) {
                $('#RESULT .collapse').first().collapse("show");
            } else {
                $('#RESULT .collapse[dm-object="' + path + '"]').collapse("show");
            }
        }

        result.object_count = function(count) {
            $('#OBJCOUNT').append(count);
        }

        result.show = function(method, path, data, status) {
            if (tr181view.input.is_checked('HTTP') || method == "CMD") {
                tr181view.result.show_http_response(method, status, data);
            } else {
                tr181view.result.message(status);
                if (data) {
                    if (method != "CMD") {
                        tr181view.result.object_count(Object.keys(data).length);
                        tr181view.result.show_objects(data);
                        tr181view.result.open();
                    }
                }
            }
        }

        result.header_get_path = function(header) {
            return header.parent().attr('dm-object');
        }

        result.param_get_path = function(param_button) {
            return param_button.parent().parent().parent().attr('dm-path');
        }

        result.param_get_name = function(param_button) {
            return param_button.parent().parent().find('th').text();
        }

        result.param_get_card = function(param_button) {
            return param_button.parent().parent().find('th').text();
        }

        result.find_card = function(dm_path) {
            return $('#RESULT .card[dm-object="' + dm_path + '"]');
        }

    }(tr181view.result = tr181view.result || {}, jQuery ));
}(window.tr181view = window.tr181view || {}, jQuery ));