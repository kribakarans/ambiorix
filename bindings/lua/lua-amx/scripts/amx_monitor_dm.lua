#!/usr/bin/env lua
                                                                   
-- Ensure lamx.so can be imported from /usr/local/lib
package.cpath = "/usr/local/lib/lua/" .. (_VERSION):gsub("Lua ", "") .. "/?.so;" .. package.cpath
package.path = "/usr/local/lib/lua/" .. (_VERSION):gsub("Lua ", "") .. "/?.lua;" .. package.path

local lamx = require 'lamx_wait_for'      
local el = lamx.eventloop.new()
local data = loadfile(arg[1])()
local current = 1

lamx.auto_connect("protected")

function write_log(text)
    local log = io.open(data.log_file, "a+")
    local uptime = io.open("/proc/uptime", "r")
    local content = uptime:read("*a")
    local seconds = content:gsub(" %d+%.%d+", " - " .. text)
    log:write(seconds)
    log:close()
    uptime:close()
end

function monitor_value(index)
    wf = lamx.bus.wait_for_value:new(data.objects[index].path, 
                                     data.objects[index].param, 
                                     data.objects[index].value)
    if data.objects[index].requires ~= nil then
        wf.requires = data.objects[index].requires
    end
    if data.objects[index].filter ~= nil then
        wf.filter = data.objects[index].filter
    end
    wf.value_is_set = function(wf, path)
        if data.objects[index].comment ~= nil then
            if type(data.objects[index].comment) == "function" then
                write_log(data.objects[index].comment(path))
            else
                write_log(data.objects[index].comment)
            end
        elseif wf.param ~= nil and wf.value ~= nil then
            write_log("Value set " .. path .. wf.param .. " = " .. wf.value)
        elseif wf.filter ~= nil then
            write_log("Filter " .. wf.filter .. " for path " .. path .. " triggered")
        else 
            write_log(path .. " tiggered")
        end
    end

    wf.object_available = function(object)
        write_log("Available " .. object)
        if current ~= 0 then
            monitor_next()
        end
    end

    wf:start()
end

function monitor_next()
    monitor_value(current)
    current = current + 1
    if data.objects[current] == nil then
        current = 0
    end
end

monitor_next()
el:start()
lamx.disconnect_all()
