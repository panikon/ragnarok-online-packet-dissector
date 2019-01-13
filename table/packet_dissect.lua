-- Copyright (C) 2019 Panikon, licensed under GNU/GPL
-- See LICENCE file in main folder
-- Packet dissect class

-- Extracts information from provided packet file
--  Provided packet file should be in the following format:
--    // packet 0x<header>
--    struct PACKET_<packet name> {
--      /* this+0x<pos> */ <type> <name>
--		[...]
--    }

dofile('bracket.lua')
bracket = require 'bracket'

-- Superclass dissect
local dissect = {
	--[[function]]['add']			= nil,
	--[[function]]['fill_table']	= nil,
	--[[function]]['new']			= nil,

	-- Table containing packet information
	-- packet_table[<header>] = {
	--	['name'] = <name>,
	--  ['server'] = <server>,
	--	['content'] = {
	--		[<pos>] = {
	--			['varname']=<varname>,
	--			['size']=<total_size>,
	--			['ctype']=<type>,
	--          ['owner']=<owner pos> (0 is PACKET_)
	--		},
	--		(...)
	--	}
	-- 	['length'] = 0, -- -1 = dynamic packet
	--	['dynamic_field'] = 0,-- Position of dynamic variable
	-- }
	['packet_table'] = {}
}

-- Verifies if given string is empty
-- @return BOOL
function is_empty(s)
	return s == nil or s == ''
end

-- Iterates through unprocessed string and fills content accordingly
-- @param content Content to be filled
-- @param stripped Fully stripped packet information string
-- @return content_iter() Iterator
-- @return stripped       Invariant state
-- @return 1              Starting position (First control value)
function process_content(content, stripped)
	local ctype_size = {
		['char']=1, ['bool']=1,  ['short']=2,
		['long']=4, ['int']=4,   ['float']=4,
		['int64']=8,['struct']=0,
		meta = { __index = function(_, key) error("Unknown type: "..key) end }
	}
	setmetatable(ctype_size, ctype_size.meta)
	-- Fixed variable position inside a given structure
	local pack_pos = 1
	-- Position of current struct the iterator is in (struct_array)
	local current_struct = 0
	local struct_array = {
		--[index] = <pack pos>
		[0] = 0 -- PACKET_
	}
	-- Generate curly brackets information
	local curly = brackets:new(stripped)
	curly:find_populate()
	curly:generate_ranges()
	--curly:display_range()

	-- Iterator
	-- @param processing    String being proceessed        (Invariant state)
	-- @param starting_pos  Current position of the cursor (Control variable)
	-- @return cur          Cursor position after operation
	local function content_iter(processing, starting_pos)
		-- Find and capture relevant information
		bcur, cur, ctype, varname = processing:find('%s*([%a%d]+)%s*([%a%d_%[%]]+)%s*', starting_pos)
		if bcur == nil or starting_pos+1 >= #processing or bcur >= cur then
			-- Strangely sometimes instead of returning nil as expected with no matches
			-- string.find returns an invalid range, with cur > bcur or even ==
			return nil -- No more matches
		end
		--print(current_struct, struct_array[current_struct], ctype, varname)
		--assert(not is_empty(ctype) and not is_empty(varname), "Malformed content "..processing:sub(bcur,cur))
		if is_empty(ctype) and is_empty(varname) then
			print(#processing, starting_pos, bcur, cur, ctype, varname)
			error("Malformed content")
		end
		-- Verifies if this variable is an array
		size_multiplier = 1
		is_array = varname:match('%[([%d%.]*)%]')
		if is_array ~= nil then
			--varname = varname:gsub('%[([%d%.]*)%]', '')
			if is_array == '...' then
				varname = varname .. "_VARIABLE_LENGTH"
			else
				size_multiplier = tonumber(is_array)
			end
		end
		-- Save variable
		if content[pack_pos] then
			print("dissect.process_content: Variable ".. varname .." already processed!")
			return cur
		end
		--print(ctype, varname)
		content[pack_pos] = {
			['varname'] = varname,
			['size'] = ctype_size[ctype]*size_multiplier,
			['ctype'] = ctype,
			['owner'] = struct_array[current_struct],
		}
		--print('('..struct_array[current_struct]..')['..pack_pos..']'..ctype..' '..varname..' {'..ctype_size[ctype]*size_multiplier..'}')
		pack_pos = pack_pos+1
		
		
		if ctype == 'struct' then
			current_struct = current_struct+1
			struct_array[current_struct] = pack_pos-1
			this_range = curly.range[current_struct]
			assert(type(this_range) == "table", "Non compatible range!")
			-- Because of the closure the curly remains the same in this iterator,
			-- so it's paramount that the character positions remain the same
			this = processing:sub(1, this_range['upper'])
			for p in content_iter, this, this_range['lower']+1 do end
			-- Jump this struct in the next pass
			cur = this_range['upper']+1
			current_struct = current_struct-1
		end
		return cur
	end
	return content_iter, stripped, 1
end


-- Adds new packet to dissect['packet_table']
-- @param name_complete Complete packet name
-- @param header Packet header
-- @param unprocessed_string Unprocessed content string (stripped)
-- @return Bool
function dissect:add(name_complete, header_str, unprocessed_string)
	-- A = Account (Login)
	-- C = Client
	-- H = Character
	-- I = Inter
	-- S = Server (any type of server)
	-- Z = Zone (Map)
	local prefix2server = {
		['S'] = 'any', ['SERVER'] = 'any',
		['A'] = 'login',
		['H'] = 'world',
		['Z'] = 'zone', ['ZH'] = 'zone',
		['AH'] = 'game_guard', -- CAH_
		meta = { __index = function(_, key) error("Unknown type: "..key) end }
	}
	setmetatable(prefix2server, prefix2server.meta)
	prefix, packet_name = name_complete:match('^(%a*)_([%a%d_]*)')
	-- Some packets don't have prefixes to them, consider them as any server
	if prefix then
		server_prefix = prefix:gsub('C','')
		server = prefix2server[server_prefix]
	else
		server = 'any'
	end
	assert(server ~= 'unknown',"Unknown server prefix in packet ".. name_complete)

	header = tonumber(header_str, 16)
	if self.packet_table[header] then
		print("dissect.add: Packet (0x"..header..")".. name_complete .." already added to packet table!")
		return false
	end
	self.packet_table[header] = {
		['name'] = name_complete,
		['content'] = {},
		--		[<pos>] = {
		--			['varname']=<varname>,
		--			['size']=<total_size>,
		--			['ctype']=<type>,
		--			['owner']=<owner pos>
		--		},
		['server'] = server,
		['length'] = 0, -- -1 = dynamic packet
		['dynamic_field'] = 0,-- Position of dynamic variable
	}
	content = self.packet_table[header]['content']
	--print(unprocessed_string)
	for cur in process_content(content, unprocessed_string) do end
	local length = 0
	-- All dynamic packets should have this second field
	if content[2] ~= nil and content[2].varname == 'PacketLength' then
		self.packet_table[header].is_dynamic = true
		length = -1
		-- The last member is always the dynamic field
		local current_pos = #content
		while true do
			if content[current_pos].owner == 0 then break end
			current_pos = current_pos-1
		end
		self.packet_table[header].dynamic_field = current_pos
	else
		for i, v in ipairs(content) do
			length = length + v.size
		end
	end
	self.packet_table[header].length = length
	return true
end

-- Prepares given string for parsing
-- @return Stripped string
function sanitize_string(s)
	s2 = s :gsub("/%*.-%*/", "")
	s2 = s2:gsub("   ", "")

	-- Sanitize packet information
	s2 = s2:gsub("struct UNUSED_PACKET_([%a%d]*)_", "struct PACKET_%1_UNUSED_")
	-- We need to use multiple patterns because it's possible to have multiple brackets inside
	-- a given packet or structs
	s2 = s2:gsub("// packet%s*0x(%x*)%s*\n%s*struct PACKET_([%a%d_]*)%s*{", ">>HEADER:0x%1\n>>PACKET_NAME:%2#")
	s2 = s2:gsub("}[\n%s]*>>HEADER", "#\n>>HEADER")
	s2 = s2:gsub("}[\n%s]*$","#")

	-- Sanitize variables
	s2 = s2:gsub('struct%s*[%a%d_]*%s*([%a%d_%[%]%.]*)','struct %1')
	s2 = s2:gsub("unsigned ", "")
	
	s2 = s2:gsub("//.-\n","\n")
	return s2
end

-- Fills dissect.packet_table with information matched from prepared string
-- @param s String containing packets to be 'dissected'
function dissect:fill_table(s)
	assert(type(s) == "string")
	prepared_string = sanitize_string(s)
	for header, packet_name, content in prepared_string:gmatch('>>HEADER:0x(%x*)%s*\n%s*>>PACKET_NAME:([%a%d_]*)%s*#([^#]*)#') do
		if self:add(packet_name, header, content) then
			--print("dissect.fill_table: ".. packet_name .." added to packet table!")
		end
	end
end

-- Create new dissect object and fills packet table if string provided
-- @param s String containing packets to be 'dissected'
function dissect:new(s, o)
	o = o or {}
	setmetatable(o, self)
	self.__index = self
	if not is_empty(s) then
		self:fill_table(s)
	end
	return o
end

return dissect
