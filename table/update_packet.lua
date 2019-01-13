-- Copyright (C) 2019 Panikon, licensed under GNU/GPL
-- See LICENCE file in main folder

--  Generates RO winsock dissect information using provided packets
--  Provided packets should be in the following format:
--    // packet 0x<header>
--    struct PACKET_<packet name> {
--      /* this+0x<pos> */ <type> <name>
--		[...]
--    }
-- Usage packet_translate.lua 'packetfile'

dofile('table_serialize.lua')
dofile('packet_dissect.lua')
dissect = require 'packet_dissect'

local packet_file = assert(io.open(arg[1],'r'))
packet_string = packet_file:read('*a')
packet_file:close()

print("Dissecting file "..arg[1])
information = dissect:new(packet_string)
print("Finished dissecting")

print("Saving to file ro_packet_table.lua")
table.save(information.packet_table, "ro_packet_table.lua")
print("Finished saving")

