(function (templates, $, undefined) {
    let fetch_html = [ ];

    let html = { };

    async function load(name, uri) {
        let response = await fetch(uri);
        if (response.ok) {
            html[name] = await response.text();
        }
    }

    templates.set = function(templates_list) {
        fetch_html = templates_list
    }

    templates.fetch = function() {
        fetch_html.forEach((value, index) => {
            if (!html['name']) {
                load(value['name'], value['uri']);
            }
        });
    }

    templates.get = function(name) {
        return html[name] || '<div></div>';
    }

    templates.load = async function(name, uri) {
        fetch_html.forEach((value, index) => {
            if (name == value['name']) {
                uri = value['uri'];
            }
        });

        if (uri) {
            let response = await fetch(uri);
            if (response.ok) {
                html[name] = await response.text();
                return await html[name];
            }
        }

        return '<div></div>';
    }
    
} (window.templates = window.templates || {}, jQuery ));
