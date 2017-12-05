-- works as of Wireshark v0.99.7
do
    local LIFX = Proto("lifx", "LIFX LAN API Protocol")
    local FRAME = Proto("lifx.frame", "Frame (LIFX)")
    local FRAME_ADDRESS = Proto("lifx.frameAddr", "Frame Address")
    local PROTOCOL_HEADER = Proto("lifx.protoHeader", "Protocol Header")
    -- (to confirm this worked, check that this protocol appears at the bottom of the "Filter Expression" dialog)
    
    -- Create the protocol fields
    local ff = FRAME.fields
    ff.size = ProtoField.uint16("lifx.size", "Packet Size", base.DEC, nil, nil, "The size of the whole packet.")
    ff.origin = ProtoField.uint8("lifx.origin", "Origin", base.DEC, nil, 0xC000, "Must be zero.") -- 0b1100000000000000
    ff.tagged = ProtoField.bool("lifx.tagged", "Tagged", 1, nil, 0x2000, "Determines usage of the Frame Address target field.") -- 0b0010000000000000
    ff.addressable = ProtoField.bool("lifx.addressable", "Addressable", 1, nil, 0x1000, "Message includes a target address: must be one (1).") -- 0b0001000000000000
    ff.protocol = ProtoField.uint16("lifx.protocol", "Protocol", base.DEC, nil, 0xFFF, "Protocol number: must be 1024 (decimal).") -- 0b0000111111111111
    ff.source = ProtoField.uint32("lifx.source", "Source", base.DEC, nil, nil, "Source identifier: unique value set by the client, used by responses.")

    local faf = FRAME_ADDRESS.fields
    faf.target = ProtoField.ether("lifx.target", "Target", "6 byte device address (MAC address) or zero (0) means all devices.")
    faf.reservedOne = ProtoField.string("lifx.reservedOne", "Reserved1")
    faf.ack_req = ProtoField.bool("lifx.ack", "ack_required", 1, nil, 0x2, "Acknowledgement message required.") -- 0b00000010
    faf.res_req = ProtoField.bool("lifx.res", "res_required", 1, nil, 0x1, "Response message required.") -- 0b00000001
    faf.sequence = ProtoField.uint8("lifx.sequence", "Sequence", base.DEC, nil, nil, "Wrap around message sequence number.")
    

    local messageTypes = {[2] = "getService", [3] = "stateService", [12] = "getHostInfo", [13] = "stateHostInfo", [14] = "getHostFirmware",
                         [15] = "stateHostFirmware", [16] = "getWifiInfo", [17] = "stateWifiInfo", [18] = "getWifiFirmware", [19] = "stateWifiFirmware",
                         [20] = "getDevicePower", [21] = "setDevicePower", [22] = "stateDevicePower", [23] = "getLabel", [24] = "setLabel", [25] = "stateLabel",
                         [32] = "getVersion", [33] = "stateVersion", [34] = "getInfo", [35] = "stateInfo", [45] = "acknowledgment", [48] = "getLocation",
                         [49] = "setLocation", [50] = "stateLocation", [51] = "getGroup", [52] = "setGroup", [53] = "stateGroup", [58] = "echoRequest",
                         [59] = "echoResponse", [101] = "get", [102] = "setColor", [103] = "setWaveform", [119] = "setWaveformOptional", [107] = "state",
                         [116] = "getLightPower", [117] = "setLightPower", [118] = "stateLightPower", [120] = "getInfrared", [121] = "stateInfrared",
                         [122] = "setInfrared", [501] = "setColorZones", [502] = "getColorZones", [503] = "stateZone", [506] = "stateMultiZone",
                         [507] = "getMoveEffect", [508] = "setMoveEffect", [509] = "stateMoveEffect"}

    local ph = PROTOCOL_HEADER.fields
    ph.reservedTwo = ProtoField.uint64("lifx.reservedTwo", "Reserved2", base.DEC, nil, nil, "Reserved.")
    ph.type = ProtoField.uint16("lifx.type", "Type", base.DEC, messageTypes, nil, "Message type determines the payload being used.")
    ph.reservedThree = ProtoField.uint16("lifx.reservedThree", "Reserved3", base.DEC, nil, nil, "Reserved.")

    local t = Field.new("lifx.type")
    
    function LIFX.dissector(tvbuffer, pinfo, treeitem)
            
        local subtreeitem = treeitem:add(LIFX, tvbuffer)
        local offset = 0

        -- Frame
        local frame = subtreeitem:add(FRAME, tvbuffer(offset, 8))
        frame:add_le(ff.size, tvbuffer(offset, 2))
        offset = offset + 2
        
        local secondBlock = tvbuffer(offset, 2)
        offset = offset + 2
        frame:add_le(ff.origin, secondBlock)
        frame:add_le(ff.tagged, secondBlock)
        frame:add_le(ff.addressable, secondBlock)
        frame:add_le(ff.protocol, secondBlock)

        frame:add_le(ff.source, tvbuffer(offset, 4))
        offset = offset + 4

        -- Frame Address
        local frame_address = subtreeitem:add(FRAME_ADDRESS, tvbuffer(offset, 16))
        frame_address:add_le(faf.target, tvbuffer(offset, 6))
        offset = offset + 8 -- 8 because mac is only 6 bytes long but field is 8 bytes in size

        frame_address:add_le(faf.reservedOne, tvbuffer(offset, 6))
        offset = offset + 6
        
        frame_address:add_le(faf.ack_req, tvbuffer(offset, 1))
        frame_address:add_le(faf.res_req, tvbuffer(offset, 1))
        offset = offset + 1

        frame_address:add_le(faf.sequence, tvbuffer(offset, 1))
        offset = offset + 1

        -- Protocol Header
        local protocol_header = subtreeitem:add(PROTOCOL_HEADER, tvbuffer(offset, 12))
        protocol_header:add_le(ph.reservedTwo, tvbuffer(offset, 8))
        offset = offset + 8

        protocol_header:add_le(ph.type, tvbuffer(offset, 2))
        offset = offset + 2

        -- Tree title append text
        local messageTypeValue = t().value
        local messageType = messageTypes[messageTypeValue]

        pinfo.cols.protocol = LIFX.name
        pinfo.cols.info = "" .. messageType .. "(" .. messageTypeValue .. ")"
        
    end

    local udp_dissector_table = DissectorTable.get("udp.port")
    udp_dissector_table:add(56700, LIFX)

end

--[[
ProtoField.uint8(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.uint16(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.uint24(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.uint32(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.uint64(abbr, [name], [base], [valuestring], [mask], [desc])

ProtoField.int8(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.int16(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.int24(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.int32(abbr, [name], [base], [valuestring], [mask], [desc])
ProtoField.int64(abbr, [name], [base], [valuestring], [mask], [desc])

ProtoField.bool(abbr, [name], [display], [valuestring], [mask], [desc])
ProtoField.float(abbr, [name], [valuestring], [desc])
ProtoField.double(abbr, [name], [valuestring], [desc])
ProtoField.string(abbr, [name], [display], [desc])

ProtoField.stringz(abbr, [name], [display], [desc])
ProtoField.bytes(abbr, [name], [display], [desc])
ProtoField.ubytes(abbr, [name], [display], [desc])
ProtoField.none(abbr, [name], [desc])
ProtoField.ether(abbr, [name], [desc]) -- i.e. MAC

Arguments
* abbr                      Abbreviated name of the field (the string used in filters).
* name (optional)           Actual name of the field (the string that appears in the tree).
* base (optional)           One of base.DEC, base.HEX or base.OCT, base.DEC_HEX, base.HEX_DEC or base.UNIT_STRING.
* valuestring (optional)    A table containing the text that corresponds to the values, or a table containing unit name for the values if base is base.UNIT_STRING.
* mask (optional)           Integer mask of this field.
* desc (optional)           Description of the field. 
* display (optional)        How wide the parent bitfield is (base.NONE is used for NULL-value).

• Message Id (4 bytes)
• Magic Value (4 bits)
• Message Format (4 bits: 1=Text 2=Binary)
• Data (variable length)

]]