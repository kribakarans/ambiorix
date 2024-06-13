#!/usr/bin/env lua
                                                                   
-- Ensure lamx.so can be imported from /usr/local/lib
package.cpath = "/usr/local/lib/lua/" .. (_VERSION):gsub("Lua ", "") .. "/?.so;" .. package.cpath

local lamx = require 'lamx'
local functions = { }
local data                                        

-- Only keep command line arguments (remove lua)
arg[-1] = nil

function string:split(sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

local function parse_parameters(index) 
    local parameters = {}

    while arg[index] ~= nil do
        local splitted = arg[index]:split("=");
        local key = splitted[1] 
        table.remove(splitted,1)
        local value = table.concat(splitted, "=")

        parameters[key] = value
        index = index + 1
    end

    return parameters
end

local function run_command()
    local data = functions[arg[1]]()
    if (data ~= nil) then 
        print(lamx.json.create(data))
        --lamx.json.dump(data)
    end
end

functions.help = function()
    print("Usage: " .. arg[0] .. " <CMD> <ARGS>")
    print("")
    print("Available commands:"
    print("    help, who_has, exists, resolve, get, 
    print("    gsdm, gidm, set, add, del, call, wait_for")
    print("")
    print("    who_has <OBJECT PATH>")
    print("    exists <OBJECT PATH>")
    print("    resolve <OBJECT PATH>")
    print("    get <OBJECT PATH> [DEPTH]")
    print("    gsdm <OBJECT PATH>")
    print("    gidm <OBJECT PATH>")
    print("    describe <OBJECT PATH>")
    print("    set <OBJECT PATH> <PARAMETER NAME>=<VALUE> [<PARAMETER NAME>=<VALUE> ...]")
    print("    add <OBJECT PATH> <PARAMETER NAME>=<VALUE> [<PARAMETER NAME>=<VALUE> ...]")
    print("    del <OBJECT PATH>")
    print("    call <OBJECT PATH> <METHOD> [<ARGUMENT NAME>=<VALUE> ...]")
    print("    wait_for <OBJECT PATH> [<OBJECT PATH> ...]")
    print("")
    print("The following commands support search and wildcard paths")
    print("  - get")
    print("  - set")
    print("  - add")
    print("  - del")
    print("  - call")
    print("")
end

functions.who_has = function()
    local path = arg[2]

    assert(path ~= nil, "Missing object path.")

    return lamx.bus.who_has(path)    
end

functions.exists = function()
    local path = arg[2]

    assert(path ~= nil, "Missing object path.")

    return lamx.bus.exists(path)    
end

functions.resolve = function()
    local path = arg[2]
    
    assert(path ~= nil, "Missing object path.")

    return lamx.bus.resolve(path)    
end

functions.get = function()
    local path = arg[2]
    local depth = arg[3] or -1
    
    assert(path ~= nil, "Missing object path.")

    return lamx.bus.get(path, depth)
end

functions.gsdm = function()
    local path = arg[2]
    
    assert(path ~= nil, "Missing object path.")

    return lamx.bus.get_supported_dm(path)
end

functions.gidm = function()
    local path = arg[2]
    
    assert(path ~= nil, "Missing object path.")

    return lamx.bus.get_instantiated_dm(path)
end

functions.describe = function()
    local path = arg[2]
    
    assert(path ~= nil, "Missing object path.")

    return lamx.bus.describe(path)
end

functions.set = function()
    local path = arg[2]
    local parameters = {}

    assert(path ~= nil, "Missing object path.")
    assert(arg[index] ~= nil, "Missing parameters.")

    parameters = parse_parameters(3)
    return lamx.bus.set(path, parameters)
end

functions.add = function()
    local path = arg[2]
    local parameters = {}

    assert(path ~= nil, "Missing object path.")
    assert(arg[index] ~= nil, "Missing parameters.")

    parameters = parse_parameters(3)
    return lamx.bus.add(path, parameters)
end

functions.del = function()
    local path = arg[2]

    assert(path ~= nil, "Missing object path.")

    return lamx.bus.del(path)
end

functions.call = function()
    local path = arg[2]
    local method = arg[3]
    local args = {}

    assert(path ~= nil, "Missing object path.")
    assert(method ~= nil, "Missing method.")

    args = parse_parameters(4)
    return lamx.bus.call(path, method, args)
end

functions.wait_for = function()
    local el = lamx.eventloop.new()
    local index = 2

    assert(arg[index] ~= nil, "Missing object path.")
    lamx.bus.wait_for(arg[index], function() el:stop() end)

    index = index + 1
    while arg[index] ~= nil do
        lamx.bus.wait_for(arg[index])
        index = index + 1
    end

    el:start()
end

--[[ 
-- The folowing functions need an event loop
-- Should they be added?
---------------------------------------------
functions.async_call = function()
    print("Not implemented yet.")
end

functions.subscribe = function()
    print("Not implemented yet.")
end
---------------------------------------------
--]]

lamx.auto_connect()

if functions[arg[1]] == nil then
    local line_nr = 0;
    for line in io.lines() do
        line_nr = line_nr + 1
        arg = line:split(" ");
        if functions[arg[1]] == nil then
            print("\27[31mInvalid command '" .. arg[1] .. "' at line " .. tostring(line_nr) .. "\27[0m")
        else 
            run_command()
        end
    end
    if line_nr == 0 then
        print("")
        print("\27[31mNo command or invalid provided.\27[0m")
        functions["help"]()
    end
else
    run_command()
end

lamx.disconnect_all()
