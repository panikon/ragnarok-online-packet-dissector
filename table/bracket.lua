-- Copyright (C) 2019 Panikon. Team, licensed under GNU/GPL
-- See LICENCE file in main folder
-- Bracket class
--  Obtains the range of each bracket pair in a given string

function trim(s)
	return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

function is_empty(s)
	return s == nil or s == ''
end

-- brackets superclass
brackets = {
	--['unprocessed'] = "",
	--['table'] = {},

	-- Bracket types
	['open'] = '{',['close'] = '}',
	-- range = [..]{ [lower], [upper] }
}

function brackets:return_table()
	return self.range
end

function brackets:display_range()
	for i, v in ipairs(self.range) do
		print('['..i..'][lower]'..v.lower..',[upper]'..v.upper)
	end
end

-- Gets the range of the open bracket in position pos in self.unprocessed
-- @return next_pos Next open bracket, 0 if none
-- @return range = { lower, upper }
function brackets:get_range(pos)
	local range = nil
	local next_pos = -1
	local count = 1

	for i, v in ipairs(self.table) do
		-- ['pos'] = pos, ['type'] = pattern
		assert(type(v) == "table")
		if pos == 0 then
			pos = v['pos']
			assert(v['type'] ~= self.close, "First bracket is a closing one!")
		elseif pos < v['pos'] then
			if v['type'] == self.open then
				-- Don't let a next_pos be overwritten
				if count == 1 and next_pos == -1 then
					next_pos = v['pos']
				end
				count = count+1
			else
				count = count-1
			end
			if v['type'] == self.close and count == 0 then
				if not range then
					-- Found the correct range range
					range = {['lower']=pos,['upper']=v['pos']}
				else -- Failed finding the next_pos (2nd range found)
					next_pos = 0
				end
				-- Search for the next position if next_pos is not valid
				count = 1
			end
			if next_pos ~= -1 and range then
				return next_pos, range
			end
		end
	end
	return 0, range
end

-- Generates ranges after a table was populated by brackets:find_populate
function brackets:generate_ranges()
	assert(not is_empty(self.unprocessed), "Unpopulated bracket!")
	next_pos = 0

	self.range = {}
	while true do
		next_pos, range = self:get_range(next_pos)
		if type(range) == 'table' then self.range[#self.range+1] = range end
		if next_pos == 0 then break end
	end
end

-- Matches a given pattern
function brackets:bmatch(pattern)
	j = 0
	self.table = {}
	for pos,typ,pos2 in self.unprocessed:gmatch(pattern) do
		if #typ > 1 then typ = trim(typ) end
		self.table[#self.table+1] = { ['pos'] = pos, ['type'] = typ }
		j = j+1
	end
	return j
end

-- Populates self.table with curly bracket information
function brackets:find_populate()
	j = self:bmatch('()([{}])()')
	assert(j%2 == 0, "Unbalanced brackets!")
end

-- Creates new curly_brackets object
-- @param s String containing string to be processed
function brackets:new(s, o)
	o = o or {}
	setmetatable(o, self)
	self.__index = self
	self.unprocessed = s
	return o
end

-- Simple unit testing
function brackets:unit_test ()
	-- Compares given range objects
	local function compare_range(t1, t2)
		return t1.lower == t2.lower and t1.upper == t2.upper
	end
	expected = {
		[1] = { ['lower']=1,['upper']=3 },
		[2] = { ['lower']=5,['upper']=19 },
		[3] = { ['lower']=7,['upper']=13 },
		[4] = { ['lower']=9,['upper']=11 },
	}
	self.unprocessed = "{ } { { { } } { } }"
	self:find_populate()
	self:generate_ranges()
	--self:display_range()
	assert(#expected == #self.range)
	for i, v in ipairs(self.range) do assert(compare_range(v,expected[i])) end
end

return brackets
