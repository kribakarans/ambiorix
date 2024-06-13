(function (conndbctrl, $, undefined) {
    let pollingID = 0;

    conndbctrl.get_device_info = async function() {
        let device = conndbview.get_device();
        let show_conninfo = conndbview.get_show_conninfo();
    
        if(device.localeCompare("NONE") == 0) {
            return;
        }
    
        let response = await tr181model.cmd("ConnDB.getDeviceInfo", {"device": device, "connection_info": true}, true, "");
        let services = response.data[0].outputArgs;
    
        if(show_conninfo) {
            conndbview.connection.startupdate();
        }
    
        for (const service in services) {
            if(service.localeCompare("Device") == 0) {
                continue;
            }
    
            conndbview.service.updaterow(service, services[service]);
    
            if(show_conninfo) {
                for (let i =0; i < services[service].Connections.length; i++) {
                    let conn = services[service].Connections[i];
                    conndbview.connection.updaterow(conn, service);
                }
            }
        }

        if(show_conninfo) {
            conndbview.connection.endupdate();
        }
    }

    conndbctrl.set_polling = function(interval) {
        clearInterval(pollingID);
        if(interval > 0) {
            pollingID = setInterval(conndbctrl.get_device_info, interval * 1000);
        }
    }

    conndbctrl.interval_updated = function() {
        let device = conndbview.get_device();

        if(device.localeCompare("NONE") == 0) {
            return;
        }

        conndbctrl.get_device_info();
        conndbctrl.set_polling(conndbview.get_interval());
    }

    conndbctrl.device_selected = function() {
        device = $(this).text();
        conndbview.update_device(device);
    }

    conndbctrl.device_select_clicked = async function () {
        let response = await tr181model.cmd("ServiceID.Config.getDevices", {}, true, "");

        conndbview.device_selection(response.data[0].outputArgs.getDevices);
    }

    conndbctrl.show_connection_clicked = function () {
        let show_conninfo = conndbview.get_show_conninfo();

        if(device.localeCompare("NONE") == 0) {
            return;
        }

        if(show_conninfo) {
            conndbview.connection.init();
            conndbctrl.get_device_info();
        } else {
            conndbview.connection.cleanup();
        }
    }

}(window.conndbctrl = window.conndbctrl || {}, jQuery ));