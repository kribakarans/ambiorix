#!/usr/bin/env lua
                                                                   
local lamx = require 'lamx'
local el = lamx.eventloop.new()
local subsription

local httpaccess = 'Device.UserInterface.HTTPAccess.'
local filter_changed = [[notification == "dm:object-changed" && 
                         path matches "UserInterface\.HTTPAccess\.[0-9]+\.$" &&
                         !contains("parameters.Status","parameters.SessionNumberOfEntries")]]

lamx.auto_connect()

local get_interface_name(intf)
    return intf_obj = lamx.bus.get(intf, 0)['Alias']
end

local firewall_update = function(event, data)
    local object = lamx.bus.get(data.path, 0)[data.path]
    local interface = get_interface_name(object.Interface)
    local fw_alias = 'cpe-httpaccess-' .. tostring(interface) .. '-' .. tostring(object.port)
    local fw_path = 'Device.Firewall.Service.[Alias=="' .. fw_alias .. '"].'
    local fw_service_path = lamx.bus.resolve(fw_path)

    local fw_config = {
        IPVersion = 4,
        Interface = object.Interface,
        Protocol = 6,
        DestPort = object.Port,
        Enable = object.Enable
    }

    if next(fw_service_path) == nil then
        fw_config["Alias"] = fw_alias
        lamx.bus.add('Device.Firewall.Service.', fw_config)
    else
        lamx.bus.set(fw_path, fw_config)
    end
end

subscription_changed = lamx.bus.subscribe(httpaccess, firewall_update, filter_changed)

el:start()

lamx.disconnect_all()
