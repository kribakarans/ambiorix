local lamx = require 'lamx'           

lamx.bus.wait_for_value = { }
lamx.bus.wait_for_value.__index = lamx.bus.wait_for_value

function lamx.bus.wait_for_value:new(path, param, expected_value) 
    local wf = {}

    setmetatable(wf, lamx.bus.wait_for_value)
    wf.path = path
    wf.param = param
    wf.value = expected_value
    wf.requires = path
    
    return wf;
end

function lamx.bus.wait_for_value:start()
    local wf = self

    local invoke_cb = function(event, data)
        if wf.value_is_set then
            local path = data.path
            if data.index then
                path = path .. tostring(data.index) .. "."
            end
            wf.value_is_set(wf, path)
        end
    end

    local check_events = function()
        local subs_filter = ""
        if wf.filter ~= nil then
            subs_filter = wf.filter
        else
            subs_filter = "parameters." .. wf.param .. ".to == '" .. tostring(wf.value) .. "'"
            subs_filter = subs_filter .. " || parameters." .. wf.param .. " == '" .. tostring(wf.value) .. "'" 
        end
        wf.subscription = lamx.bus.subscribe(wf.path, invoke_cb, subs_filter)
    end

    local check_value = function() 
        local retval = false
        if wf.value ~= nil and wf.param ~= nil then
            local values = lamx.bus.get(wf.path .. wf.param, 0)
            for object_path,params in pairs(values) do
                if params[wf.param] == wf.value then
                    if wf.value_is_set then
                        wf.value_is_set(wf, object_path)
                    end
                    retval = true
                end
            end
        end
        return retval
    end

    local object_available = function()
        if wf.object_available then
            wf.object_available(wf.requires)
        end
        check_events()
        check_value()
    end

    lamx.bus.wait_for(wf.requires, object_available)
end

return lamx