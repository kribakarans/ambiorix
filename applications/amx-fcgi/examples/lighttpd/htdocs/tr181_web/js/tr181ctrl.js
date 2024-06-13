(function (tr181ctrl, $, undefined) {
    function handle_error(method, path, err) {
        if (tr181view.input.is_checked('HTTP')) {
            tr181view.result.show(method, path, undefined, err.message);
        } else {
            tr181view.result.error(err);
        }
    }

    async function get(method, path) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(path, method));
            let response = await tr181model.get(path);
            tr181view.result.show(method, path, response.data, response.status);

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    async function set(method, path, params) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(path, method), { parameters: params });
            let response = await tr181model.set(path, params);
            if (tr181model.is_ok(response.status) && tr181view.input.is_checked('FETCH')) {
                tr181ctrl.execute_request("GET", path);
            } else {
                tr181view.result.show(method, path, response.data, response.status);
            }
            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    async function add(method, path, params) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(path, method), { parameters: params });
            let response = await tr181model.add(path, params);
            if (tr181model.is_ok(response.status) && tr181view.input.is_checked('FETCH')) {
                tr181ctrl.execute_request("GET", path);
            } else {
                tr181view.result.show(method, path, [response.data], response.status);
            }

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    async function del(method, path) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(path, method));
            let response = await tr181model.del(path);
            let temp = path.split('.');
            temp.pop();
            temp.pop();
            path = temp.join('.') + '.';
            if (tr181model.is_ok(response.status) && tr181view.input.is_checked('FETCH')) {
                tr181ctrl.execute_request("GET", path);
            } else {
                tr181view.result.show(method, path, response.data, response.status);
            }

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    async function cmd(method, path, params, toggles) {
        try {
            let msg = {
                command: path,
                commandkey: "",
                sendresp: true,
                inputArgs: params
            };
            console.log(toggles);
            if (toggles["ASYNC"]) {
                msg.commandkey = document.uuid();
            }
            tr181view.result.show_http_request(method, tr181model.uri(path, method), msg);
            let response = await tr181model.cmd(path, msg.inputArgs, !toggles["FIRE"], msg.commandkey);
            tr181view.result.show(method, path, response.data, response.status);

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    async function upload(method, file) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(file.name, method));
            let response = await tr181model.upload(file);
            tr181view.result.show(method, file.name, response.data, response.status);

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, file.name, err);
            return await err.status;
        }
    }

    async function download(method, path) {
        try {
            tr181view.result.show_http_request(method, tr181model.uri(path, method));
            let response = await tr181model.download(path);
            tr181view.result.show(method, path, response.data, response.status);

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error(method, path, err);
            return await err.status;
        }
    }

    function build_object(obj, propertylist) {
        propertylist.forEach(
            function(prop) {
                obj[prop.elementProperty] = prop.elementValue;
            }
        )
    }

    tr181ctrl.handle_event = function(event) {
        let data = JSON.parse(event.data);
        tr181view.result.show_event(data.path, data.event_name, data, event.type);
    }

    tr181ctrl.execute_request = async function(method, path, params, toggles) {
        let funcs = {
            "GET": get,
            "SET": set,
            "ADD": add,
            "DELETE": del,
            "CMD": cmd
        }

        tr181view.result.clear();
        
        if (funcs[method]) {
            return funcs[method](method, path, params, toggles);
        }
    }

    tr181ctrl.execute_upload = async function(method, file) {
        tr181view.result.clear();
        
        return upload(method, file);
    }

    tr181ctrl.execute_download = async function(method, path) {
        tr181view.result.clear();
        
        return download(method, path);
    }

    tr181ctrl.run_batch = async function(msg) {
        tr181view.result.clear();

        try {
            tr181view.result.show_http_request("BATCH", tr181model.uri("", "BATCH"), msg);
            let response = await tr181model.batch(msg);
            tr181view.result.show("BATCH", "", response.data, response.status);

            return tr181model.status_code(await response.status);
        } catch(err) {
            handle_error("BATCH", "", err);
            return await err.status;
        }

    }

    tr181ctrl.build_property_list = function(list, data, name = 'elementProperty', value = 'elementValue') {
        for(let param_name in data) {
            if (data.hasOwnProperty(param_name)) {
                let se = {};
                se[name] = param_name;
                se[value] = data[param_name];
                list.push(se);
            }
        }
    }

    tr181ctrl.to_cmd_args = function(data) {
        let result = [];
        this.build_property_list(result, data, "argName", "argValue");
        return result;
    }

    tr181ctrl.logout = async function() {
        let host = location.protocol.concat("//").concat(window.location.host);
        let uri = host.concat("/session/logout");
        tr181view.clear();
        setTimeout(function(){ 
            uri = host.concat("/tr181ui.html");
            fetch(uri).then(tr181view.init)
        }, 500);
        try {
            await fetch(uri); 
        } catch(err) {
            console.log(err)
        }
    }

}(window.tr181ctrl = window.tr181ctrl || {}, jQuery ));