--[[

  Copyright (c) 2020, G.A. vd. Hoorn
  All rights reserved.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

  ---

  Primitive Wireshark dissector for the Fanuc "High Speed Position Output"
  protocol (R891).

  TODO:

   - add support for XML (ie: non-binary) packets
   - improve documententation.
]]
do
	-- feature detection
	assert (set_plugin_info and Pref.range, "This dissector (Fanuc High Speed Position Output (R891)) requires Wireshark 3.x or newer.")


	-- 
	-- constants
	-- 
	local DISSECTOR_VERSION             = "0.1.5"

	local DEFAULT_R891_PORT             = 80
	local FANUCROB_OUI                  = 0x00e0e4
	local GEFANUCA_OUI                  = 0x000991

	local DEF_NUM_AXES                  = 6
	local MAX_NUM_AXES                  = 9


	-- bit positions
	local TYPE_BIT_ACT_TCP   = 0
	local TYPE_BIT_CMD_TCP   = 1
	local TYPE_BIT_ACT_JOINT = 2
	local TYPE_BIT_CMD_JOINT = 3
	local TYPE_BIT_VARIABLES = 4


	-- 
	-- constant -> string rep tables
	-- 


	local type_bit_str = {
		[TYPE_BIT_ACT_TCP  ] = "Actual TCP",
		[TYPE_BIT_CMD_TCP  ] = "Commanded TCP",
		[TYPE_BIT_ACT_JOINT] = "Actual joint angles",
		[TYPE_BIT_CMD_JOINT] = "Commanded joint angles",
		[TYPE_BIT_VARIABLES] = "Variables",
	}




	-- 
	-- misc
	-- 

	-- cache globals to local for speed
	local _F=string.format

	-- wireshark API globals
	local Pref = Pref

	-- minimal default config
	local config = {
		disp_unused = true,
		num_axes = DEF_NUM_AXES,
		ignore_mac = false,
	}

	-- register version info with wireshark
	set_plugin_info({version = DISSECTOR_VERSION})




	-- 
	-- Protocol object creation and setup
	-- 
	local p_fanuc_hspo = Proto("FRR891", "Fanuc Robotics - High Speed Position Output (R891)")

	-- preferences
	p_fanuc_hspo.prefs["udp_ports"] = Pref.range("UDP Ports", _F("%d", DEFAULT_R891_PORT), _F("UDP ports the dissector should be registered for (default: %d).", DEFAULT_R891_PORT), 65535)
	p_fanuc_hspo.prefs["disp_unused"] = Pref.bool ("Show reserved fields", true, "Should reserved fields be added to dissection tree?")
	p_fanuc_hspo.prefs["num_axes"] = Pref.uint("Number of axes", DEF_NUM_AXES, "Maximum nr of axes to display fields for (all values will always be dissected).")
	p_fanuc_hspo.prefs["ignore_mac"] = Pref.bool("Dissect all packets", true, "Do not check MAC address of incoming packets (ie: treat all packets on the registered ports as R891 packets).")




	-- 
	-- protocol fields
	--
	local fields = p_fanuc_hspo.fields

	fields.version          = ProtoField.uint16("frr891.version"       , "Version"     , base.DEC_HEX, nil         , nil, "Version of the protocol")
	fields.size             = ProtoField.uint16("frr891.size"          , "Size"        , base.DEC    , nil         , nil, "Size (number of sections?)")
	fields.index            = ProtoField.uint32("frr891.index"         , "Index"       , base.DEC    , nil         , nil, "Sequence number")
	fields.clock            = ProtoField.uint32("frr891.clock"         , "Clock"       , base.DEC    , nil         , nil, "Controller clock (in microseconds)")
	fields.type             = ProtoField.uint16("frr891.type"          , "Data Types"  , base.HEX    , nil         , nil, "Data types in the packet (ie: TCP, Joint Angles, etc)")
	  fields.type_act_tcp   = ProtoField.uint16("frr891.type.act_tcp"  , _F("%-23s", type_bit_str[TYPE_BIT_ACT_TCP])  , base.DEC, nil, bit.lshift(1, TYPE_BIT_ACT_TCP)  , type_bit_str[TYPE_BIT_ACT_TCP])
	  fields.type_cmd_tcp   = ProtoField.uint16("frr891.type.cmd_tcp"  , _F("%-23s", type_bit_str[TYPE_BIT_CMD_TCP])  , base.DEC, nil, bit.lshift(1, TYPE_BIT_CMD_TCP)  , type_bit_str[TYPE_BIT_CMD_TCP])
	  fields.type_act_joint = ProtoField.uint16("frr891.type.act_joint", _F("%-23s", type_bit_str[TYPE_BIT_ACT_JOINT]), base.DEC, nil, bit.lshift(1, TYPE_BIT_ACT_JOINT), type_bit_str[TYPE_BIT_ACT_JOINT])
	  fields.type_cmd_joint = ProtoField.uint16("frr891.type.cmd_joint", _F("%-23s", type_bit_str[TYPE_BIT_CMD_JOINT]), base.DEC, nil, bit.lshift(1, TYPE_BIT_CMD_JOINT), type_bit_str[TYPE_BIT_CMD_JOINT])
	  fields.type_vars      = ProtoField.uint16("frr891.type.vars"     , _F("%-23s", type_bit_str[TYPE_BIT_VARIABLES]), base.DEC, nil, bit.lshift(1, TYPE_BIT_VARIABLES), type_bit_str[TYPE_BIT_VARIABLES])

	fields.group            = ProtoField.uint16("frr891.group", "Motion Group", base.DEC, nil, nil, "Motion group")

	fields.pos_x            = ProtoField.float("frr891.pos.x", "X", "TCP X coordinate")
	fields.pos_y            = ProtoField.float("frr891.pos.y", "Y", "TCP Y coordinate")
	fields.pos_z            = ProtoField.float("frr891.pos.z", "Z", "TCP Z coordinate")
	fields.pos_w            = ProtoField.float("frr891.pos.w", "W", "TCP W coordinate")
	fields.pos_p            = ProtoField.float("frr891.pos.p", "P", "TCP P coordinate")
	fields.pos_r            = ProtoField.float("frr891.pos.r", "R", "TCP R coordinate")

	fields.pos_j1           = ProtoField.float("frr891.pos.j1", "J1", "J1 coordinate")
	fields.pos_j2           = ProtoField.float("frr891.pos.j2", "J2", "J2 coordinate")
	fields.pos_j3           = ProtoField.float("frr891.pos.j3", "J3", "J3 coordinate")
	fields.pos_j4           = ProtoField.float("frr891.pos.j4", "J4", "J4 coordinate")
	fields.pos_j5           = ProtoField.float("frr891.pos.j5", "J5", "J5 coordinate")
	fields.pos_j6           = ProtoField.float("frr891.pos.j6", "J6", "J6 coordinate")
	fields.pos_j7           = ProtoField.float("frr891.pos.j7", "J7", "J7 coordinate")
	fields.pos_j8           = ProtoField.float("frr891.pos.j8", "J8", "J8 coordinate")
	fields.pos_j9           = ProtoField.float("frr891.pos.j9", "J9", "J9 coordinate")

	fields.status           = ProtoField.uint32("frr891.status", "Status", base.DEC_HEX, nil, nil, "Status")
	fields.io               = ProtoField.uint32("frr891.io"    , "I/O"   , base.DEC_HEX, nil, nil, "I/O")




	-- field extractors
	local f_eth_src = Field.new("eth.src")

	local f_size  = Field.new("frr891.size")
	local f_index = Field.new("frr891.index")
	local f_type  = Field.new("frr891.type")

	local f_group = Field.new("frr891.group")

	local f_type_act_tcp   = Field.new("frr891.type.act_tcp")
	local f_type_cmd_tcp   = Field.new("frr891.type.cmd_tcp")
	local f_type_act_joint = Field.new("frr891.type.act_joint")
	local f_type_cmd_joint = Field.new("frr891.type.cmd_joint")
	local f_type_vars      = Field.new("frr891.type.vars")




	local function is_pkt_from_robot()
		-- TODO: should GE Fanuc OUI be checked as well?
		return (f_eth_src().range(0, 3):uint() == FANUCROB_OUI)
	end


	local function extract_pkt_version(buf, offset)
		return buf(offset, 2):uint()
	end


	local function stringify_flagbits(bit_val, bit_tab)
		-- TODO: this loses order of flags
		local temp = {}
		for k, v in pairs(bit_tab) do
			if (bit.band(bit_val, bit.lshift(1, k)) > 0) then table.insert(temp, v) end
		end
		return table.concat(temp, ", ")
	end


	local function add_float_with_label(tree, field, buf, label, unit)
		-- if only add_packet_field(..) worked for floats ..
		return tree:add(field, buf):set_text(_F("%s: %10.4f %s", label, buf:float(), unit))
	end


	local function disf_tcp(buf, pkt, tree, offset, label)
		local offset_ = offset
		local lt = tree

		-- motion group
		lt:add(fields.group, buf(offset_, 2))
		offset_ = offset_ + 2

		local pos_tree = lt:add(buf(offset_, 6*4), label)

		-- TODO: what about E1, E2 and E3?
		add_float_with_label(pos_tree, fields.pos_x, buf(offset_, 4), "X", "mm")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_y, buf(offset_, 4), "Y", "mm")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_z, buf(offset_, 4), "Z", "mm")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_w, buf(offset_, 4), "W", "deg")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_p, buf(offset_, 4), "P", "deg")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_r, buf(offset_, 4), "R", "deg")
		offset_ = offset_ + 4

		-- status and IO
		lt:add(fields.status, buf(offset_, 4))
		offset_ = offset_ + 4
		lt:add(fields.io, buf(offset_, 4))
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function disf_joints(buf, pkt, tree, offset, label)
		local offset_ = offset
		local lt = tree

		-- motion group
		lt:add(fields.group, buf(offset_, 2))
		offset_ = offset_ + 2

		local pos_tree = lt:add(buf(offset_, 9*4), label)

		-- TODO: we hard-code the units here (not sure there would be any way
		-- for us to determine which units a field would have)
		add_float_with_label(pos_tree, fields.pos_j1, buf(offset_, 4), "J1", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j2, buf(offset_, 4), "J2", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j3, buf(offset_, 4), "J3", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j4, buf(offset_, 4), "J4", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j5, buf(offset_, 4), "J5", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j5, buf(offset_, 4), "J5", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j6, buf(offset_, 4), "J6", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j8, buf(offset_, 4), "J8", "rad")
		offset_ = offset_ + 4
		add_float_with_label(pos_tree, fields.pos_j9, buf(offset_, 4), "J9", "rad")
		offset_ = offset_ + 4

		-- status and io
		lt:add(fields.status, buf(offset_, 4))
		offset_ = offset_ + 4
		lt:add(fields.io, buf(offset_, 4))
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	local function parse(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- header tree
		local hdr_tree = lt:add(buf(offset_, 12), "Header")

		-- version, size, index and clock
		hdr_tree:add(fields.version, buf(offset_, 2))
		offset_ = offset_ + 2
		hdr_tree:add(fields.size, buf(offset_, 2))
		offset_ = offset_ + 2
		hdr_tree:add(fields.index, buf(offset_, 4))
		offset_ = offset_ + 4
		hdr_tree:add(fields.clock, buf(offset_, 4)):append_text(" us")
		offset_ = offset_ + 4

		-- special treatment for type
		local tbt_buf = buf(offset_, 2)
		local type_bit_tree = hdr_tree:add(fields.type, tbt_buf)
		type_bit_tree:add(fields.type_act_tcp  , tbt_buf)
		type_bit_tree:add(fields.type_cmd_tcp  , tbt_buf)
		type_bit_tree:add(fields.type_act_joint, tbt_buf)
		type_bit_tree:add(fields.type_cmd_joint, tbt_buf)
		type_bit_tree:add(fields.type_vars     , tbt_buf)
		offset_ = offset_ + 2

		-- append high bit flags to bitfield parent item
		if f_type().value ~= 0 then
			type_bit_tree:append_text(_F(" (%s)", stringify_flagbits(f_type().value, type_bit_str)))
		end

		-- dissect correct type of data, depending on pkt type
		-- TODO: dissect variables
		if f_type_act_tcp().value == 1 then
			offset_ = offset_ + disf_tcp(buf, pkt, lt, offset_, "Position: Actual TCP")
		end
		if f_type_cmd_tcp().value == 1 then
			offset_ = offset_ + disf_tcp(buf, pkt, lt, offset_, "Position: Commanded TCP")
		end
		if f_type_act_joint().value == 1 then
			offset_ = offset_ + disf_joints(buf, pkt, lt, offset_, "Position: Actual Joint Angles")
		end
		if f_type_cmd_joint().value == 1 then
			offset_ = offset_ + disf_joints(buf, pkt, lt, offset_, "Position: Command Joint Angles")
		end

		-- mark bytes we haven't dissected as such
		local zlen = (buf:len() - (offset_ - offset))
		if (zlen > 0) then
			lt:add(buf(offset_, zlen), _F("Undissected (%u bytes)", zlen))
			offset_ = offset_ + zlen
		end

		-- fixup body buffer highlight length
		-- TODO: should this be done here or in main dissector function?
		lt:set_len(offset_ - offset)

		-- nr of bytes we consumed
		return (offset_ - offset)
	end


	-- actual dissector method
	function p_fanuc_hspo.dissector(buf, pkt, tree)
		--print("---------------")
		-- check buffer len
		local buf_len = buf:len()
		--print("buffer length: " .. buf_len)
		-- anything less than the size of a header will not do
		if (buf_len <= 0) or (buf_len < 48) then return end

		-- make sure this packet came from a Fanuc controller
		if (not is_pkt_from_robot()) and (not config.ignore_mac) then
			print(p_fanuc_hspo.name .. ": ignoring pkt " .. pkt.number .. " (not a FANUC MAC)")
			return false
		end

		-- either we resume dissecting, or we start fresh
		local offset = pkt.desegment_offset or 0
		--print("offset: " .. offset)

		-- keep dissecting as long as there are bytes available
		while true do
			-- TODO: we assume single pkt per datagram here
			pkt_len = buf_len
			--print("pkt_len: " .. pkt_len)

			-- '0' is an invalid packet length, so abort
			if pkt_len == 0 then
				print(p_fanuc_hspo.name .. ": invalid length (0) for pkt " .. pkt.number)
				return false
			end

			-- make sure we support the version of R891
			pkt_version = extract_pkt_version(buf, offset)
			if pkt_version ~= 0 then
				-- TODO: add some expert info or other warning
				print(p_fanuc_hspo.name .. ": unsupported pkt version (" 
					.. pkt_version .. ") for pkt " .. pkt.number)
				return false
			end

			-- TODO: is reassembly over UDP even supported?
			-- If we don't have enough bytes in the buffer, signal
			-- caller by setting appropriate fields in 'pkt' argument
			-- NOTE: this should never happen, as the docs state (imply)
			--       that pkts will always be sent in single datagrams,
			--       and don't cross datagram boundaries, but you never know
			local nextpkt = offset + pkt_len
			----print("nextpkt: " .. nextpkt)
			if (nextpkt > buf_len) then
				pkt.desegment_len = nextpkt - buf_len
				pkt.desegment_offset = offset
				return
			end

			-- add protocol to tree
			local prot_tree = tree:add(p_fanuc_hspo, buf(offset, pkt_len))

			-- add info to top pkt view
			pkt.cols.protocol = p_fanuc_hspo.name

			-- dissect pkt
			local res = parse(buf, pkt, prot_tree, offset)

			-- add some extra info to the protocol line in the packet treeview
			local dtype = stringify_flagbits(f_type().value, type_bit_str)
			local mgrp = f_group().value
			local seq = f_index().value
			prot_tree:append_text(_F(", %s (grp %d), %u bytes", dtype, mgrp, pkt_len))

			-- use offset in buffer to determine if we need to append to or set
			-- the info column
			if (offset > 0) then
				pkt.cols.info:append(_F("; %s (grp %d, pkt %d)", dtype, mgrp, seq))
			else
				pkt.cols.info = _F("%s (grp %d, pkt %d)", dtype, mgrp, seq)
			end

			-- increment 'read pointer' and stop if we've dissected all bytes 
			-- in the buffer
			offset = nextpkt
			if (offset == buf_len) then return end

		-- end-of-dissect-while
		end

	-- end-of-dissector
	end


	-- init routine
	function p_fanuc_hspo.init()
		-- update config from prefs
		config.disp_unused = p_fanuc_hspo.prefs["disp_unused"]
		config.num_axes = p_fanuc_hspo.prefs["num_axes"]
		config.ignore_mac = p_fanuc_hspo.prefs["ignore_mac"]

		-- register the dissector
		local udp_dissector_table = DissectorTable.get("udp.port")
		udp_dissector_table:add(p_fanuc_hspo.prefs.udp_ports, p_fanuc_hspo)
	end
end
