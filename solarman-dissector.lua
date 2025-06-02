local proto = Proto("Solarman", "Solarman PV Inverters")

---@enum Command
local commands = {
	[0x11] = "HELLO_RESP",
	[0x12] = "PUSH_DATA_RESP",
	[0x13] = "PUSH_UNKNOWN1_RESP",
	[0x15] = "MODBUS_RESP",
	[0x17] = "KEEP_ALIVE_RESP",
	[0x18] = "PUSH_UNKNOWN2_RESP",
	[0x41] = "HELLO",
	[0x42] = "PUSH_DATA",
	[0x43] = "PUSH_UNKNOWN1",
	[0x45] = "MODBUS_REQ",
	[0x47] = "KEEP_ALIVE",
	[0x48] = "PUSH_UNKNOWN2",
}

local fields = proto.fields
fields.payload_len          = ProtoField.uint16("solarman.payload_len", "Payload Length", base.DEC)
fields.unknown1             = ProtoField.bytes("solarman.unknown1", "Unknown 1")
fields.command              = ProtoField.uint8("solarman.command", "Command", base.HEX, commands)
fields.seq_req              = ProtoField.uint8("solarman.seq_req", "Sequence Num (Request)", base.DEC)
fields.seq_resp             = ProtoField.uint8("solarman.seq_resp", "Sequence Num (Response)", base.DEC)
fields.serial               = ProtoField.uint32("solarman.serial", "Device Serial", base.DEC)
fields.checksum             = ProtoField.uint8("solarman.checksum", "Checksum", base.HEX)
fields.unknown_payload      = ProtoField.bytes("solarman.unknown_payload", "Unknown Payload", base.SPACE)
fields.empty_payload        = ProtoField.bytes("solarman.empty.payload", "Payload (unused)", base.SPACE)
fields.time_resp_unknown1   = ProtoField.bytes("solarman.time_resp.unknown1", "Unknown", base.SPACE)
fields.time_resp_unknown2   = ProtoField.bytes("solarman.time_resp.unknown2", "Unknown", base.SPACE)
fields.time_resp_current_ts = ProtoField.absolute_time("solarman.time_resp.current_ts", "Current Timestamp", base.LOCAL)
fields.hello_unknown1       = ProtoField.bytes("solarman.hello.unknown1", "Unknown", base.SPACE)
fields.hello_unknown2       = ProtoField.bytes("solarman.hello.unknown2", "Unknown", base.SPACE)
fields.hello_unknown3       = ProtoField.bytes("solarman.hello.unknown3", "Unknown", base.SPACE)
fields.hello_module_ver     = ProtoField.stringz("solarman.hello.module_ver", "Module Version")
fields.hello_system_ver     = ProtoField.stringz("solarman.hello.system_ver", "Extended System Version")
fields.hello_mac_addr       = ProtoField.bytes("solarman.hello.mac_addr", "MAC Address", base.COLON)
fields.hello_ip_addr        = ProtoField.stringz("solarman.hello.ip_addr", "Local IP Address")
fields.push_unknown1_unk1   = ProtoField.bytes("solarman.push_unknown1.unknown1", "Unknown", base.SPACE)
fields.push_unknown1_unk2   = ProtoField.bytes("solarman.push_unknown1.unknown2", "Unknown", base.SPACE)
fields.push_unknown1_ssid   = ProtoField.stringz("solarman.push_unknown1.ssid", "WiFi SSID")
fields.push_unknown2_unk1   = ProtoField.bytes("solarman.push_unknown2.unknown1", "Unknown", base.SPACE)
fields.push_unknown2_unk2   = ProtoField.bytes("solarman.push_unknown2.unknown2", "Unknown", base.SPACE)
fields.push_unknown2_ts     = ProtoField.absolute_time("solarman.push_unknown2.ts", "Timestamp", base.LOCAL)
fields.time_inv_uptime      = ProtoField.relative_time("solarman.time.inv_uptime", "Uptime (Inverter)")
fields.time_log_uptime      = ProtoField.relative_time("solarman.time.log_uptime", "Uptime (Logger)")
fields.time_timestamp_unk   = ProtoField.absolute_time("solarman.time.timestamp_unknown", "Unknown Timestamp", base.LOCAL)
fields.push_data_unk1       = ProtoField.bytes("solarman.push_data.unknown1", "Unknown", base.SPACE)
fields.push_data_unk2       = ProtoField.bytes("solarman.push_data.unknown2", "Unknown", base.SPACE)
fields.push_data_unk3       = ProtoField.bytes("solarman.push_data.unknown3", "Unknown", base.SPACE)
fields.push_data_unk4       = ProtoField.bytes("solarman.push_data.unknown4", "Unknown", base.SPACE)
fields.push_data_counter    = ProtoField.uint16("solarman.push_data.counter", "Counter")
fields.push_data_serial     = ProtoField.string("solarman.push_data.serial", "Serial (Logger)")
fields.modbus_req_unk1      = ProtoField.bytes("solarman.modbus_req.unknown1", "Unknown", base.SPACE)
fields.modbus_resp_unk1     = ProtoField.bytes("solarman.modbus_resp.unknown", "Unknown", base.SPACE)



local astro_proto = Proto("TM-L800Mi", "Astro Energy TM-L800Mi Register Dumps")
local astro_reg_decoders = {}
local function makeRegisterField(reg, name, desc, unit, scaler)
	scaler = scaler or 1
	local field = ProtoField.float("solarman.astro" .. name, desc)
	astro_proto.fields[name] = field
	---@param buf TvbRange
	---@param tree TreeItem
	astro_reg_decoders[#astro_reg_decoders + 1] = function(buf, tree)
		local data = buf(reg * 2, 2)
		tree:add(field, data, data:uint() * scaler):append_text(" "):append_text(unit)
	end
end
makeRegisterField( 0, "v1", "PV1 Voltage", "V", 0.1)
makeRegisterField( 1, "v2", "PV2 Voltage", "V", 0.1)
makeRegisterField( 5, "i1", "PV1 Current", "(unscaled)")
makeRegisterField( 6, "i2", "PV2 Current", "(unscaled)")
makeRegisterField( 9, "i_out", "Out Current", "A", 0.01)
makeRegisterField(11, "v_out", "Out Voltage", "V", 0.1)
makeRegisterField(13, "f_out", "Out Frequency", "Hz", 0.01)
makeRegisterField(15, "unknown_reg", "Unknown register", "")
makeRegisterField(20, "wh_daily", "Total Energy Produced", "Wh", 17.35529493) -- FIXME: what kind of scaler is this?
makeRegisterField(22, "temperature", "Temperature", "(unscaled)")
makeRegisterField(23, "num_inputs", "Num Inputs", "")

---@param buf Tvb
local function validate(buf)
	if buf:reported_len() ~= buf:captured_len() then
		return "Truncated packet"
	end
	if buf:reported_len() < 13 then
		return "Expected at least 13 bytes of packet data"
	end
	if buf(-1):uint() ~= 0x15 then
		return "Packt doesn't end with expected trailing byte; segmented or merged packets are NYI"
	end
end

---@param buf TvbRange
local function checksum(buf)
	local cs = 0
	for i = 0, buf:len() - 1 do
		cs = cs + buf(i, 1):uint()
	end
	return bit.band(cs, 0xFF)
end

---@param buf TvbRange
---@param tree TreeItem
local function unkownDecoder(buf, tree)
	tree:add(fields.unknown_payload, buf())
end

---@param buf TvbRange
---@param tree TreeItem
local function emptyDecoder(buf, tree)
	tree:add(fields.empty_payload, buf())
end

---@param buf TvbRange
---@param tree TreeItem
local function timeReplyDecoder(buf, tree)
	tree:add(fields.time_resp_unknown1, buf(0, 2))
	tree:add_le(fields.time_resp_current_ts, buf(2, 4))
	tree:add(fields.time_resp_unknown2, buf(6))
end

---@param buf TvbRange
---@param tree TreeItem
local function helloDecoder(buf, tree)
	tree:add(fields.hello_unknown1, buf(0, 19))
	tree:add(fields.hello_module_ver, buf(19, 40))
	tree:add(fields.hello_mac_addr, buf(59, 6))
	tree:add(fields.hello_ip_addr, buf(65, 16))
	tree:add(fields.hello_unknown2, buf(81, 8))
	tree:add(fields.hello_system_ver, buf(89, 40))
	tree:add(fields.hello_unknown3, buf(129))
end

---@param buf TvbRange
---@param tree TreeItem
local function pushUnknown1Decoder(buf, tree)
	tree:add(fields.push_unknown1_unk1, buf(0, 15))
	tree:add_le(fields.push_unknown1_ssid, buf(15, 30))
	tree:add(fields.push_unknown1_unk2, buf(45))
end

---@param buf TvbRange
---@param tree TreeItem
local function pushUnknown2Decoder(buf, tree)
	tree:add(fields.push_unknown2_unk1, buf(0, 9))
	tree:add_le(fields.push_unknown2_ts, buf(9, 4))
	tree:add(fields.push_unknown2_unk2, buf(14))
end

local function registerDecoder(buf, parent_tree)
	local tree = parent_tree:add(astro_proto, buf, "Astro Energy TM-L800Mi data")
	for _, reg in ipairs(astro_reg_decoders) do
		reg(buf, tree)
	end
end

---@param buf TvbRange
---@param tree TreeItem
local function decodeTimeBlock(buf, tree)
	tree:add_le(fields.time_inv_uptime, buf(0, 4))
	tree:add_le(fields.time_log_uptime, buf(4, 4))
	tree:add_le(fields.time_timestamp_unk, buf(8, 4))
end

---@param buf TvbRange
---@param tree TreeItem
local function pushDataDecoder(buf, tree)
	tree:add(fields.push_data_unk1, buf(0, 3))
	decodeTimeBlock(buf(3, 12), tree)
	tree:add(fields.push_data_unk2, buf(15, 2))
	tree:add_le(fields.push_data_counter, buf(17, 2))
	tree:add(fields.push_data_unk3, buf(19, 2))
	tree:add(fields.push_data_serial, buf(21, 16))
	registerDecoder(buf(37, 120), tree)
	tree:add(fields.push_data_unk4, buf(157))
end

---@param buf TvbRange
---@param tree TreeItem
local function modbusRequestDecoder(buf, tree, pinfo)
	tree:add(fields.modbus_req_unk1, buf(0, 15))
    Dissector.get("mbrtu"):call(buf(15):tvb(), pinfo, tree)
end

---@param buf TvbRange
---@param tree TreeItem
local function modbusResponseDecoder(buf, tree, pinfo)
	tree:add(fields.modbus_resp_unk1, buf(0, 2))
	decodeTimeBlock(buf(2, 12), tree)
	print(buf:len())
	if buf:len() == 139 then -- very likely an Astro Energy device that just always dumps all of its 60 registers
		registerDecoder(buf(17, 120), tree)
	end
    Dissector.get("mbrtu"):call(buf(14):tvb(), pinfo, tree)
end

local decoders = {
	HELLO              = helloDecoder,
	HELLO_RESP         = timeReplyDecoder,
	KEEP_ALIVE         = emptyDecoder,
	KEEP_ALIVE_RESP    = timeReplyDecoder,
	PUSH_DATA          = pushDataDecoder,
	PUSH_DATA_RESP     = timeReplyDecoder,
	PUSH_UNKNOWN1      = pushUnknown1Decoder,
	PUSH_UNKNOWN1_RESP = timeReplyDecoder,
	PUSH_UNKNOWN2      = pushUnknown2Decoder,
	PUSH_UNKNOWN2_RESP = timeReplyDecoder,
	MODBUS_REQ         = modbusRequestDecoder,
	MODBUS_RESP        = modbusResponseDecoder,
}


function proto.dissector(buf, pinfo, parent_tree)
	if buf:captured_len() == 0 or buf(0, 1):uint() ~= 0xa5 then
		return 0
	end
	local tree = parent_tree:add(proto, buf(), "Solarman Data")
	local validationError = validate(buf)
	if validationError then
		tree:add_expert_info(PI_MALFORMED, PI_ERROR, validationError)
		return
	end
	local payload_len_tree = tree:add_le(fields.payload_len, buf(1, 2))
	local payload_len = buf(1, 2):le_uint()
	if buf:captured_len() ~= payload_len + 13 then
		payload_len_tree:add_expert_info(PI_MALFORMED, PI_WARN, ("Expected payload length of %d, packet may be truncated, segmented, or contain multiple packets (NYI)"):format(buf:captured_len() - 13))
	end
	tree:add(fields.unknown1, buf(3, 1))
	tree:add(fields.command, buf(4, 1))
	tree:add(fields.seq_req, buf(5, 1))
	tree:add(fields.seq_resp, buf(6, 1))
	tree:add_le(fields.serial, buf(7, 4))
	local packetType = commands[buf(4, 1):uint()]
	local payload = buf(11, payload_len)
	local decoder = packetType and decoders[packetType] or unkownDecoder
	decoder(payload, tree, pinfo)
	local expected_cs = checksum(buf(1, buf:captured_len() - 3))
	local cs = buf(buf:captured_len() - 2, 1)
	local csTree = tree:add(fields.checksum, cs)
	if cs:uint() == expected_cs then
		csTree:append_text(" [correct]")
	else
		csTree:append_text(" [incorrect]")
		csTree:add_expert_info(PI_CHECKSUM, PI_WARN, ("Expected checksum 0x%02x"):format(expected_cs))
	end
	-- Set at the end because the modbus dissector overrides them otherwise
	pinfo.cols.info = packetType
	pinfo.cols.protocol = "Solarman"
end

local dt = DissectorTable.get("tcp.port") or error("tcp.port dissector table not found")

dt:add(10000, proto)
dt:add(8899, proto)
