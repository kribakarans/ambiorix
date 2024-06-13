#!/usr/bin/env lua
                                                                   
-- Ensure lamx.so can be imported from /usr/local/lib
package.cpath = "/usr/local/lib/lua/" .. (_VERSION):gsub("Lua ", "") .. "/?.so;" .. package.cpath

-- Only keep command line arguments (remove lua and script name)
arg[0] = nil
arg[-1] = nil

local lamx = require 'lamx'                                        
local el = lamx.eventloop.new()

lamx.auto_connect("protected")
lamx.bus.wait_for(arg, function() el:stop() end)
el:start()
lamx.disconnect_all()