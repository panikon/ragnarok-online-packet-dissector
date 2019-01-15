-- Copyright (C) 2019 Tyr Panikon, licensed under GNU/GPL
-- See LICENCE file in main folder

dofile("table_serialize.lua")
packet_table = table.load("ro_packet_table.lua")

ro_protocol = Proto("RO", "Ragnarok Online")
dofile("ro_tap.lua")

packet_header = ProtoField.uint16("ro.header", "Header", base.HEX)
packet_name = ProtoField.string("ro.packet_name", "Packet Name", base.ASCII)
server_type = ProtoField.string("ro.server_type", "Server Type", base.ASCII)
ro_protocol.fields = { packet_header, packet_name, server_type }

-- Ports used when dissecting packets
port_list = {
	6900, 6901, -- Login
	7000, 7001, -- World
	4501, 4502  -- Zone
}

-- Displays buffer in given subtree using content as dissect information
-- @param subtree Current subtree
-- @param pos     Buffer offset
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
function display_content(subtree, buffer, pos, packet)
	content = packet.content
	display_tree = {[0] = subtree}

	local ctype_meta = { __index = function(_, key) error("Unknown type: "..key) end }
	local ctype2tbrange = {
		['char'] =  function (s) return TvbRange.le_uint(s)  end, ['struct']= function (s) return TvbRange.bytes(s)    end,
		['bool'] =  function (s) return TvbRange.le_uint(s)  end, ['short'] = function (s) return TvbRange.le_uint(s)  end,
		['long'] =  function (s) return TvbRange.le_uint(s)  end, ['int']   = function (s) return TvbRange.le_uint(s)  end,
		['float']=  function (s) return TvbRange.le_float(s) end, ['int64'] = function (s) return TvbRange.le_int64(s) end,
		['cstring']=function (s) return TvbRange.string(s)   end, 
	}	
	setmetatable(ctype2tbrange, ctype_meta)
	local ctype2ftype = {
		['char'] =ftypes.STRING, ['struct']=ftypes.NONE,
		['bool'] =ftypes.BOOLEAN,['short'] =ftypes.UINT16,
		['long'] =ftypes.UINT32, ['int']   =ftypes.UINT32,
		['float']=ftypes.FLOAT,  ['int64'] =ftypes.INT64,
	}
	setmetatable(ctype2ftype, ctype_meta)
	function field(varname, ctype, size, owner)
		-- Create a protocol field for this variable
		field_name  = string.format("ro.%s", varname)
		ro_protocol.fields[varname] = ProtoField.new(field_name, 'RO', ctype2ftype[ctype])
		range = buffer(pos,size)
		assert(type(display_tree[owner]) == "userdata", "INVALID TREE")
		if ctype == 'char' and size > 1 then ctype = 'cstring' end
		display_tree[owner]:add(varname, ctype2tbrange[ctype](range))
		--subtree:add(varname, buffer(pos, size):ctype2tbrange[ctype]())
	end

	if packet.len == -1 then
		dynamic_start = 0
		remaining_len = 0
		expected_len = buffer(2, 4):le_uint()
	end
	for i, v in ipairs(content) do
		if v.ctype == 'struct' then
			-- Create a subtree for the information contained here
			display_tree[i] = subtree:add(ro_protocol, buffer(), v.varname)
		else
			field(v.varname, v.ctype, v.size, v.owner)
		end
		if packet.len == -1 then
			if i == packet.dynamic_field then
				remaining_len = expected_len - pos
				if v.ctype == 'struct' then
					dynamic_start = i+1
				else -- This variable is the only segment that is dynamic
					field(v.varname, v.ctype, remaining_len, v.owner)
				end
			end
		end
		pos = pos+v.size
	end
	-- Only try to display dynamic packets that have multiple dynamic fields
	if packet.len == -1 and dynamic_start ~= 0 then
		remaining_len = expected_len - pos
		j = dynamic_field

		while remaining_len > 0 do
			current = packet[j]
			field(current.varname, current.ctype, current.size, current.owner)
			pos = pos+current.size
			remaining_len = remaining_len - pos
			j = j + 1
		end
	end
end

-- Main dissector
-- @param Buffer      packet buffer (Tvb object)
-- @param pinfo       Columns of the packet list
-- @param main_tree   Node of the tree view (TreeItem object)
function ro_protocol.dissector(buffer, pinfo, main_tree)
	-- RO Packets, are in LE
	-- First WORD (2 bytes) is the header, the following bytes are the payload
	-- If the packet is dynamic the next WORD is the total packet length

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
	local packet = {}

	length = buffer:len()
	if length == 0 then return end
	pinfo.cols.protocol = ro_protocol.name
	-- Create our subtree
	local subtree = main_tree:add(ro_protocol, buffer(), "RO Protocol Data")

	header = buffer(0, 2):le_uint()

	assert(type(packet_table) == "table")
	
	if not packet_table[header] then
		packet[header] = {
			['name']    = 'Unknown packet',
            ['server']  = 'Unknown server',
		    ['content'] = nil
		}
	else
		packet = packet_table[header]
	end

	subtree:add_le(packet_header, buffer(0,2))
	subtree:add(packet_name):append_text(string.format("%s",packet.name))
	subtree:add(server_type):append_text(string.format("%s",packet.server))
	if not packet.content then
		return
	end

	local content = packet.content
	pos = 0
	display_content(subtree, buffer(), pos, packet)
end

-- Register the protocol to the expected ports
local tcp_port = DissectorTable.get("tcp.port")
for i, v in ipairs(port_list) do
	tcp_port:add(v, ro_protocol)
end
