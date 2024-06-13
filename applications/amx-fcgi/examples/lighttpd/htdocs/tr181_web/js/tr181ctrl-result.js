 (function (tr181crtl, $, undefined) {
    (function (result, $, undefined) {

        result.handle_header_button = function() {
            let path = tr181view.result.header_get_path($(this));
            let action = $(this).attr('btn-action');
            switch(action) {
                case "get":
                    tr181view.input.add_card(path, "GET");
                    tr181ctrl.execute_request("GET", path);
                    break;
                case 'delete':
                    tr181view.input.add_card(path, "DELETE");
                    break;
            }
        }

        result.on_set_clicked = function() {
            let dm_path = tr181view.result.param_get_path($(this));
            let param_name = tr181view.result.param_get_name($(this));
            let card = tr181view.input.find_card(dm_path, "SET");
            let param_name_field = undefined;

            if (card.length == 0) {
                card = tr181view.input.add_card(dm_path, "SET");
                param_name_field = card.find('input').first();
                param_name_field.val(param_name);
                card.find('input').last().focus();
            } else {
                let param = tr181view.input.card_find_param(card, param_name);
                if (param) {
                    param.find('input').last().focus();
                } else {
                    param = tr181view.input.add_param(card);
                    param.find('input').first().val(param_name);
                    param.find('input').last().focus();
                }
            }
        }

    } (tr181ctrl.result = tr181ctrl.result || {}, jQuery ));
}(window.tr181ctrl = window.tr181ctrl || {}, jQuery ));