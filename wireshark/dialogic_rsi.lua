-------------------------------------------------------------------------------
-- script-name: dialogic_rsi.lua
--
-- author: Maxim Klimovich
-- 
-- Version: 1.0
--
-------------------------------------------------------------------------------
--[[

    This code is a plugin for Wireshark, to dissect Dialogic RSI link
    protocol messages over TCP.

	Installation:
	Copy dialogic_rsi.lua into %USERPROFILE%\AppData\Roaming\Wireshark\Plugins\

]]----------------------------------------

local p_rsi = Proto("rsi","Dialogic RSI")
local f = p_rsi.fields

local sccp_prim_types = {
	[1] = "N-UNITDATA request",
	[2] = "N-UNITDATA indication",
	[3] = "N-NOTICE indication",
	[4] = "N-CONNECT request",
	[5] = "N-CONNECT indication",
	[6] = "N-CONNECT response",
	[7] = "N-CONNECT confirmation",
	[8] = "N-DATA request"
}

f.msg_type		= ProtoField.uint16("rsi.type",		"Message type",	base.HEX)
f.id			= ProtoField.uint16("rsi.id",		"ID",			base.DEC)
f.src			= ProtoField.uint8 ("rsi.src",		"Src",			base.HEX)
f.dst			= ProtoField.uint8 ("rsi.dst",		"Dst",			base.HEX)
f.rsp_req		= ProtoField.uint16("rsi.rsp_req",	"rsp_req",		base.HEX)
f.hclass		= ProtoField.uint8 ("rsi.hclass",	"hclass",		base.HEX)
f.status		= ProtoField.uint8 ("rsi.status",	"Status",		base.HEX)
f.err_info		= ProtoField.uint32("rsi.err_info",	"err_info",		base.HEX)
f.reserved		= ProtoField.uint32("rsi.reserved",	"reserved",		base.HEX)
f.len			= ProtoField.uint16("rsi.len",		"Length",		base.DEC)

f.tmp			= ProtoField.uint16("rsi.tmp",		"First param",	base.DEC)
f.text			= ProtoField.string("rsi.data",		"Data")
f.sccp_prim_type= ProtoField.uint8 ("rsi.sccp.primtype",	"Primitive type",	base.DEC, sccp_prim_types)
f.sccp_retopt	= ProtoField.uint8("rsi.sccp.ret_opt",		"Return option",	base.DEC,
									{ [0] = "Discard Message on error", [1] = "Return Message on error"})

-- Message types
MsgTypeDescr = {}
MsgTypeDescr[0x8742] = "SCP_MSG_RX_IND"
MsgTypeDescr[0xc740] = "SCP_MSG_TX_REQ"
  
-- Primitive based SCCP from Dialogic
local p_sccp	= Proto("rsi.sccp","SCCP")
local sccp		= p_sccp.fields
sccp.prim_type	= ProtoField.uint8 ("rsi.sccp.primtype",	"Primitive type",	base.DEC, sccp_prim_types)
sccp.retopt		= ProtoField.uint8("rsi.sccp.ret_opt",		"Return option",	base.DEC,
									{ [0] = "Discard Message on error", [1] = "Return Message on error"})

sccp.ai			= ProtoField.uint8("rsi.sccp.ai",		"AI",			base.HEX)
sccp.ai_reserved= ProtoField.uint8("rsi.sccp.ai.reserved",	"Reserved for national use",	base.HEX, nil, 0x0080)
sccp.ai_ri		= ProtoField.uint8("rsi.sccp.ai.ri",		"Routing Indicator",			base.HEX, {[0]="Route on GT",[1]="Route on SSN"}, 0x0040)
sccp.ai_gti		= ProtoField.uint8("rsi.sccp.ai.gti",		"Global Title Indicator",		base.HEX, nil, 0x003C)
sccp.ai_ssni	= ProtoField.uint8("rsi.sccp.ai.ssni",		"SubSystem Number Indicator",	base.HEX, {[0]="SSN not present",[1]="SSN present"}, 0x0002)
sccp.ai_pci		= ProtoField.uint8("rsi.sccp.ai.pci",		"Point Code Indicator",			base.HEX, {[0]="Point Code not present",[1]="Point Code present"}, 0x0001)

sccp.pc			= ProtoField.uint16("rsi.sccp.pc",		"PC",		base.DEC, nil, 0x3FFF)
sccp.ssn		= ProtoField.uint8("rsi.sccp.ssn",		"SubSystem Number",		base.DEC)

-- no sense to use "Protocol" data filed, it does not allow fields containerization. 
-- The only difference is grey highiligting of protocols (ordinary fields is white)
--sccp.called			= ProtoField.protocol("rsi.sccp.called", "Called Party address")
sccp.called			= ProtoField.none("rsi.sccp.called",  "Called Party address")
sccp.calling		= ProtoField.none("rsi.sccp.calling", "Calling Party address")
sccp.userdata		= ProtoField.none("rsi.sccp.userdata", "User Data")

sccp.called_ai		= ProtoField.uint8("rsi.sccp.called.ai",		"AI",			base.HEX)
sccp.called_reserved= ProtoField.uint8("rsi.sccp.called.reserved",	"Reserved for national use",base.HEX, nil, 0x0080)
sccp.called_ri		= ProtoField.uint8 ("rsi.sccp.called.ri",		"Routing Indicator",			base.HEX, {[0]="Route on GT",[1]="Route on SSN"}, 0x0040)
sccp.called_gti		= ProtoField.uint8 ("rsi.sccp.called.gti",		"Global Title Indicator",		base.HEX, nil, 0x003C)
sccp.called_ssni	= ProtoField.uint8 ("rsi.sccp.called.ssni",		"SubSystem Number Indicator",	base.HEX, {[0]="SSN not present",[1]="SSN present"}, 0x0002)
sccp.called_pci		= ProtoField.uint8 ("rsi.sccp.called.pci",		"Point Code Indicator",			base.HEX, {[0]="Point Code not present",[1]="Point Code present"}, 0x0001)
sccp.called_pc		= ProtoField.uint16("rsi.sccp.called.pc",		"PC",							base.DEC, nil, 0x3FFF)
sccp.called_ssn		= ProtoField.uint8 ("rsi.sccp.called.ssn",		"SubSystem Number",				base.DEC)
sccp.called_gt		= ProtoField.none  ("rsi.sccp.called.gt",		"Global Title")
sccp.called_tt		= ProtoField.uint8 ("rsi.sccp.called.tt",		"Translation Type",				base.HEX)
sccp.called_np		= ProtoField.uint8 ("rsi.sccp.called.np",		"Numbering Plan",				base.HEX, {[1]="ISDN/Telephony"}, 0x00F0)
sccp.called_es		= ProtoField.uint8 ("rsi.sccp.called.es",		"Encoding Scheme",				base.HEX, {[1]="BCD, odd number of digits",
																												[2]="BCD, even number of digits"}, 0x000F)
sccp.called_nai		= ProtoField.uint8 ("rsi.sccp.called.nai",		"Nature of Address Indicator",	base.HEX, {[0]="Unknown",
																												[1]="Subscriber number",
																												[2]="Reserved for national use",
																												[3]="National number",
																												[4]="International number"}, 0x007F)
sccp.called_edigits	= ProtoField.none  ("rsi.sccp.called.encdigits","Called Party Digits")
sccp.called_digits	= ProtoField.string("rsi.sccp.called.digits","Called GT Digits")
																												
sccp.calling_ai		= ProtoField.uint8("rsi.sccp.calling.ai",		"AI",			base.HEX)
sccp.calling_reserved= ProtoField.uint8("rsi.sccp.calling.reserved","Reserved for national use",base.HEX, nil, 0x0080)
sccp.calling_ri		= ProtoField.uint8 ("rsi.sccp.calling.ri",		"Routing Indicator",			base.HEX, {[0]="Route on GT",[1]="Route on SSN"}, 0x0040)
sccp.calling_gti	= ProtoField.uint8 ("rsi.sccp.calling.gti",		"Global Title Indicator",		base.HEX, nil, 0x003C)
sccp.calling_ssni	= ProtoField.uint8 ("rsi.sccp.calling.ssni",	"SubSystem Number Indicator",	base.HEX, {[0]="SSN not present",[1]="SSN present"}, 0x0002)
sccp.calling_pci	= ProtoField.uint8 ("rsi.sccp.calling.pci",		"Point Code Indicator",			base.HEX, {[0]="Point Code not present",[1]="Point Code present"}, 0x0001)
sccp.calling_pc		= ProtoField.uint16("rsi.sccp.calling.pc",		"PC",							base.DEC, nil, 0x3FFF)
sccp.calling_ssn	= ProtoField.uint8 ("rsi.sccp.calling.ssn",		"SubSystem Number",				base.DEC)
sccp.calling_gt		= ProtoField.none  ("rsi.sccp.calling.gt",		"Global Title")
sccp.calling_tt		= ProtoField.uint8 ("rsi.sccp.calling.tt",		"Translation Type",				base.HEX)
sccp.calling_np		= ProtoField.uint8 ("rsi.sccp.calling.np",		"Numbering Plan",				base.HEX, {[1]="ISDN/Telephony"}, 0x00F0)
sccp.calling_es		= ProtoField.uint8 ("rsi.sccp.calling.es",		"Encoding Scheme",				base.HEX, {[1]="BCD, odd number of digits",
																												[2]="BCD, even number of digits"}, 0x000F)
sccp.calling_nai	= ProtoField.uint8 ("rsi.sccp.calling.nai",		"Nature of Address Indicator",	base.HEX, {[0]="Unknown",
																												[1]="Subscriber number",
																												[2]="Reserved for national use",
																												[3]="National number",
																												[4]="International number"}, 0x007F)
sccp.calling_edigits= ProtoField.none  ("rsi.sccp.calling.encdigits","Called Party Digits")
sccp.calling_digits	= ProtoField.string("rsi.sccp.calling.digits","Called GT Digits")


function p_rsi.dissector (buf, pktinfo, root)
	if buf:len() == 0 then return end
	pktinfo.cols.protocol = p_rsi.name

	-- Add GCT header
	header_tree = root:add(p_rsi, buf(0, 20))
	--nodeType, msg_type = header_tree:add_packet_field( f.msg_type, buf(0, 2), ENC_BIG_ENDIAN )
	-- add_packet_field does not work. Bug in Wireshark, the second return valie is always nil. Have to use 2 commands instead
	nodeType = header_tree:add(f.msg_type,	buf(0, 2))
	local msg_type = buf:range(0, 2):uint()
	if MsgTypeDescr[msg_type] == nil then
		nodeType:append_text(" [Unknown message]")
	else
		nodeType:append_text(" ["..MsgTypeDescr[msg_type].."]")
	end
    header_tree:add(f.id,		buf(2,2))
    header_tree:add(f.src,		buf(4,1))
    header_tree:add(f.dst,		buf(5,1))
    header_tree:add(f.rsp_req,	buf(6,2))
    header_tree:add(f.hclass,	buf(8,1))
    header_tree:add(f.status,	buf(9,1))
    header_tree:add(f.err_info, buf(10,4))
    header_tree:add(f.reserved, buf(14,4))
    header_tree:add(f.len, 		buf(18,2))
	local sccp_len = buf(18,2):uint()

	if ((msg_type ~= 0x8742) and (msg_type ~= 0xc740)) then
		return
	end
	-- Add SCCP
	local pos = 20
	local sccp_tree = root:add(p_sccp, buf(pos, sccp_len))
	local sccp_message_type = buf(pos,1):uint()
	sccp_tree:add(f.sccp_prim_type,	buf(pos, 1))
	pos = pos + 1

	local param_type
	local param_len
	while buf(pos,1):uint() ~= 0 do
		param_type = buf(pos,1):uint()
		pos = pos + 1
		param_len = buf(pos,1):uint()
		pos = pos + 1
		if 		param_type == 1 then -- Return option
			sccp_tree:add(f.sccp_retopt,	buf(pos,param_len))
		elseif	param_type == 4 then -- Calling address
			local cgpn_tree = sccp_tree:add( sccp.calling, buf(pos, param_len) )
			decodeCgPN( buf, pktinfo, cgpn_tree, pos-1 )	-- Rewind back to include len param
		elseif	param_type == 5 then -- Called address
			local cdpn_tree = sccp_tree:add( sccp.called, buf(pos, param_len) )
			decodeCdPN( buf, pktinfo, cdpn_tree, pos-1 )    -- Rewind back to include len param
			--decodeCxPN( buf, pktinfo, cdpn_tree, pos-1 )    -- Rewind back to include len param
		elseif	param_type == 6 then -- User data
			-- Add TCAP
            local userdata_tree = sccp_tree:add( sccp.userdata, buf(pos, param_len) )
			Dissector.get("tcap"):call( buf(pos,param_len):tvb(), pktinfo, root )
		else
		end
		pos = pos + param_len
	end

end

decodeCdPN = function(buf, pktinfo, root, offset)
	local pos = offset
	local len = buf(pos,1):uint()
	pos = pos + 1
	local AI = buf(pos,1):uint()
	local ai_tree = root:add(sccp.called_ai, buf(pos, 1) )
	ai_tree:add(sccp.called_reserved,buf(pos, 1) )
	ai_tree:add(sccp.called_ri, 	buf(pos, 1) )
	ai_tree:add(sccp.called_gti,	buf(pos, 1) )
	local gti = bit32.extract( AI, 2, 4 )
	ai_tree:add(sccp.called_ssni,	buf(pos, 1) )
	ai_tree:add(sccp.called_pci, 	buf(pos, 1) )
	pos = pos + 1
	if ( bit32.btest( AI, 0x01) ) then	-- has PC in address
		field_size = 2
		root:add_le(sccp.called_pc, 	buf(pos, field_size) )
		pos = pos  + field_size
	end
	if ( bit32.btest( AI, 0x02) ) then	-- has SSN in address
		field_size = 1
		root:add(sccp.called_ssn,		buf(pos, field_size) )
		pos = pos  + field_size
	end
	local gt_size = len + offset - pos + 1
	local gt_tree = root:add( sccp.called_gt, buf(pos, gt_size) )
	gt_tree:append_text(" "..string.format( "0x%02x", gti ).." (".. gt_size .." bytes)")
	if gti == 4 then
		gt_tree:add( sccp.called_tt, buf( pos, 1) )
		pos = pos + 1
		gt_tree:add( sccp.called_np, buf( pos, 1) )
		gt_tree:add( sccp.called_es, buf( pos, 1) )
		local encoding = bit32.extract( buf(pos,1):uint(), 0, 4 )
		pos = pos + 1
		gt_tree:add( sccp.called_nai, buf( pos, 1) )
		pos = pos + 1
		digits_node = gt_tree:add( sccp.called_edigits, buf( pos, gt_size - 3) )
		local digitStart = pos
		local digits = ""
		local digitsHexBuf = ""
		while pos <= offset + len do
			digit = buf(pos,1):uint()
			digits = digits..string.format( "%d", bit32.extract(digit, 0, 4) )
			digitsHexBuf = digitsHexBuf..string.format( "%02X", bit32.extract(digit, 0, 4) + 48 )
			if ((pos ~= offset + len) or (encoding == 2)) then
				digits = digits..string.format( "%d", bit32.extract(digit, 4, 4) )
				digitsHexBuf = digitsHexBuf..string.format( "%02X", bit32.extract(digit, 4, 4) + 48 )
			end
			pos = pos + 1
		end
		digits_node:append_text( ": "..digits )
		buf = ByteArray.new(digitsHexBuf)
		tvbDigits = buf:tvb("Called number digits")
		digits_node:add(sccp.called_digits, tvbDigits(0,tvbDigits:len()))
	end
end

decodeCgPN = function(buf, pktinfo, root, offset)
	local pos = offset
	local len = buf(pos,1):uint()
	pos = pos + 1
	local AI = buf(pos,1):uint()
	local ai_tree = root:add(sccp.calling_ai, buf(pos, 1) )
	ai_tree:add(sccp.calling_reserved,buf(pos, 1) )
	ai_tree:add(sccp.calling_ri, 	buf(pos, 1) )
	ai_tree:add(sccp.calling_gti,	buf(pos, 1) )
	local gti = bit32.extract( AI, 2, 4 )
	ai_tree:add(sccp.calling_ssni,	buf(pos, 1) )
	ai_tree:add(sccp.calling_pci, 	buf(pos, 1) )
	pos = pos + 1
	if ( bit32.btest( AI, 0x01) ) then	-- has PC in address
		field_size = 2
		root:add_le(sccp.calling_pc, 	buf(pos, field_size) )
		pos = pos  + field_size
	end
	if ( bit32.btest( AI, 0x02) ) then	-- has SSN in address
		field_size = 1
		root:add(sccp.calling_ssn,		buf(pos, field_size) )
		pos = pos  + field_size
	end
	local gt_size = len + offset - pos + 1
	local gt_tree = root:add( sccp.calling_gt, buf(pos, gt_size) )
	gt_tree:append_text(" "..string.format( "0x%02x", gti ).." (".. gt_size .." bytes)")
	if gti == 4 then
		gt_tree:add( sccp.calling_tt, buf( pos, 1) )
		pos = pos + 1
		gt_tree:add( sccp.calling_np, buf( pos, 1) )
		gt_tree:add( sccp.calling_es, buf( pos, 1) )
		local encoding = bit32.extract( buf(pos,1):uint(), 0, 4 )
		pos = pos + 1
		gt_tree:add( sccp.calling_nai, buf( pos, 1) )
		pos = pos + 1
		digits_node = gt_tree:add( sccp.calling_edigits, buf( pos, gt_size - 3) )
		local digitStart = pos
		local digits = ""
		local digitsHexBuf = ""
		while pos <= offset + len do
			digit = buf(pos,1):uint()
			digits = digits..string.format( "%d", bit32.extract(digit, 0, 4) )
			digitsHexBuf = digitsHexBuf..string.format( "%02X", bit32.extract(digit, 0, 4) + 48 )
			if ((pos ~= offset + len) or (encoding == 2)) then
				digits = digits..string.format( "%d", bit32.extract(digit, 4, 4) )
				digitsHexBuf = digitsHexBuf..string.format( "%02X", bit32.extract(digit, 4, 4) + 48 )
			end
			pos = pos + 1
		end
		digits_node:append_text( ": "..digits )
		buf = ByteArray.new(digitsHexBuf)
		tvbDigits = buf:tvb("Calling number digits")
		digits_node:add(sccp.calling_digits, tvbDigits(0,tvbDigits:len()))
	end
end

 
-- Initialization routine
function p_rsi.init()
end

local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add("9000-9015", p_rsi)
