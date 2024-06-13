(function (conndbview, $, undefined) {
    async function build_page() {
        let header = await window.templates.load("header");
        let settings = await window.templates.load("settings");
        
        $('body .content').append(header);
        $('body .content').append(settings);

        tr181model.open_session("admin","admin");

        $('#DEVICE_SELECT').click(conndbctrl.device_select_clicked);
        $('#SHOW_CONN').click(conndbctrl.show_connection_clicked);
        $('#POLL_INTERVAL').on('change input', conndbctrl.interval_updated);
    }

    conndbview.update_device = async function(device) {
        $('#DEVICE_SELECT').text(device);
        if(device.localeCompare("NONE") == 0) {
            conndbview.service.cleanup();
            conndbview.connection.cleanup();
            conndbctrl.set_polling(0);
        } else {
            conndbview.service.init();
            if(conndbview.get_show_conninfo()) {
                conndbview.connection.init();
            }
            conndbctrl.get_device_info();
            conndbctrl.set_polling(conndbview.get_interval());
        }
    }

    conndbview.device_selection= function(devices) {
        $('#MENU').empty();
        
        let menu_item_none = $(window.templates.get("dropdown-item").format('NONE'));
        $('#MENU').append(menu_item_none);

        for (let i = 0; i < devices.length; i++) {
            let device = devices[i];
            if(device != null) {
                let menu_item = $(window.templates.get("dropdown-item").format(device));
                $('#MENU').append(menu_item);
            }
        }

        $('.dropdown-item').click(conndbctrl.device_selected);
    }

    conndbview.get_device = function() {
        return $('#DEVICE_SELECT').text();
    }

    conndbview.get_interval = function() {
        return $('#POLL_INTERVAL').val();
    }

    conndbview.get_show_conninfo = function() {
        return $('#SHOW_CONN').is(':checked'); 
    }

    conndbview.init = async function() {        
        let fetch_html = [
            { name: "header", uri: "/conndb/templates/header.html" },
            { name: "settings", uri: "/conndb/templates/settings.html" },
            { name: "dropdown-item", uri: "/conndb/templates/dropdown-item.html" },
            { name: "connection-table", uri: "/conndb/templates/connection-table.html" },
            { name: "service-table", uri: "/conndb/templates/service-table.html" },
        ];

        window.templates.set(fetch_html);
        await build_page();
        window.templates.fetch();
    }
}(window.conndbview = window.conndbview || {}, jQuery ));