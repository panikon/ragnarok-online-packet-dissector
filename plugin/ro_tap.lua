-- Copyright (C) 2019 Tyr Panikon, licensed under GNU/GPL
-- See LICENCE file in main folder

ro_tap = Listener.new("ip", "ro")

-- File handle used when dumping information
local file_handle = nil

-- Tap entry point
-- @param pinfo	Columns of the packet list
-- @param tvb	Buffer information
-- @param ip	IP information
function ro_tap.packet(pinfo, tvb, ip)

	if not file_handle then
		file_handle = Dumper.new_for_current('ro_extracted.pcap')
	end
	file_handle:dump_current()
	file_handle:flush()

end

-- Called at the end of the process
function ro_tap.reset()
	if file_handle then file_handle:close() end
end
