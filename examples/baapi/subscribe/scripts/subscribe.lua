local pretty = require 'pl.pretty'
local lamx = require 'lamx'
local sub

lamx.auto_connect()

local el = lamx.eventloop.new()

local print_event = function(event, data)
   print("Notification received from " .. event);
   print("Event " .. tostring(event))
   pretty.dump(data)
end

local objects_available = function()
    print("Wait done - object " .. arg[1] .. " is available");
    if arg[2] then 
        sub = lamx.bus.subscribe(arg[1], print_event, arg[2]);
    else
        sub = lamx.bus.subscribe(arg[1], print_event);
    end
end

print("Wait until object " .. arg[1] .. " is available");
lamx.bus.wait_for(arg[1], objects_available)

el:start()

lamx.disconnect_all()