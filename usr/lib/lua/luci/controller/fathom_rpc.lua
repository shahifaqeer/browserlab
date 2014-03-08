--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>
Copyright 2008 Jo-Philipp Wich <xm@leipzig.freifunk.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

$Id: rpc.lua 8902 2012-08-08 09:48:53Z jow $
]]--

--[[
Fathom RPC module for LuCi based on the LuCi json-rcp module.

Authors: Anna

last-edit: saru sgrover@gatech.edu 9/5/2013
]]--

local require = require
local pairs = pairs
local print = print
local pcall = pcall
local table = table

module "luci.controller.fathom_rpc"

function index()
	local function authenticator(validator, accs)
		local auth = luci.http.formvalue("auth", true)
		if auth then -- if authentication token was given
			local sdat = luci.sauth.read(auth)
			if sdat then -- if given token is valid
				if sdat.user and luci.util.contains(accs, sdat.user) then
					return sdat.user, auth
				end
			end
		end
		luci.http.status(403, "Forbidden")
	end

	-- /cgi-bin/luci/fathom path
	local rpc = node("fathom")
	rpc.sysauth = "root"
	rpc.sysauth_authenticator = authenticator
	rpc.notemplate = true

	-- each entry creates a new path, e.g.
	-- /cgi-bin/luci/fathom/bismark

	-- Anna: exporting sys mostly for testing purposes
	entry({"fathom", "sys"}, call("rpc_sys"))
	entry({"fathom", "bismark"}, call("rpc_bm"))
	entry({"fathom", "auth"}, call("rpc_auth")).sysauth = false
end

function rpc_auth()
	local jsonrpc = require "luci.jsonrpc"
	local sauth   = require "luci.sauth"
	local http    = require "luci.http"
	local sys     = require "luci.sys"
	local ltn12   = require "luci.ltn12"
	local util    = require "luci.util"

	local loginstat

	local server = {}
	server.challenge = function(user, pass)
		local sid, token, secret

		if sys.user.checkpasswd(user, pass) then
			sid = sys.uniqueid(16)
			token = sys.uniqueid(16)
			secret = sys.uniqueid(16)

			http.header("Set-Cookie", "sysauth=" .. sid.."; path=/")

			-- Anna: adding this allows scripts with any origin
			-- to call the measurement API (cross-domain)
			-- Maybe put some restriction here ?
			http.header("Access-Control-Allow-Origin","*")

			sauth.reap()
			sauth.write(sid, {
				user=user,
				token=token,
				secret=secret
			})
		end

		return sid and {sid=sid, token=token, secret=secret}
	end

	server.login = function(...)
		local challenge = server.challenge(...)
		return challenge and challenge.sid
	end

	http.prepare_content("application/json")
	ltn12.pump.all(jsonrpc.handle(server, http.source()), http.write)
end

function rpc_sys()
	local sys     = require "luci.sys"
	local jsonrpc = require "luci.jsonrpc"
	local http    = require "luci.http"
	local ltn12   = require "luci.ltn12"

	http.prepare_content("application/json")
	-- Anna: same caveats as above - this is potential security risk?
	http.header("Access-Control-Allow-Origin","*")
	ltn12.pump.all(jsonrpc.handle(sys, http.source()), http.write)
end

function rpc_bm()
	local jsonrpc = require "luci.jsonrpc"
	local http    = require "luci.http"
	local ltn12   = require "luci.ltn12"

    local bm = require "luci.bismark"

	http.prepare_content("application/json")
	-- Anna: same caveats as above - this is potential security risk?
	http.header("Access-Control-Allow-Origin","*")
	ltn12.pump.all(jsonrpc.handle(bm, http.source()), http.write)
end
