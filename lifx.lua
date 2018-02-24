-- Author: Maurice Fahn
-- Created: 2017-12-04
--
-- Tested and working with Wireshark Version 2.4.3.
-- This Wireshark Plugin dissects packets of the LIFX LAN Protocol (https://lan.developer.lifx.com/docs/header-description).
-- It attaches to UDP port 56700 (the default port for LIFX lights).

-- Filter for Set/State Packets:
-- (lifx.type & 0x1 or (lifx.type == 102 or lifx.type == 50 or lifx.type == 52 or lifx.type == 58 or lifx.type == 102 or lifx.type == 118 or lifx.type == 122 or lifx.type == 506 or lifx.type == 508 or lifx.type == 702)) and !(lifx.type == 23 or lifx.type == 51 or lifx.type == 101 or lifx.type == 507)
-- 
-- Filter for Get Packets:
-- !((lifx.type & 0x1 or (lifx.type == 102 or lifx.type == 50 or lifx.type == 52 or lifx.type == 58 or lifx.type == 102 or lifx.type == 118 or lifx.type == 122 or lifx.type == 506 or lifx.type == 508 or lifx.type == 702)) and !(lifx.type == 23 or lifx.type == 51 or lifx.type == 101 or lifx.type == 507))


do

    local LIFX = Proto("lifx", "LIFX LAN Protocol")
    local FRAME = Proto("lifx.frame", "Frame (LIFX)")
    local FRAME_ADDRESS = Proto("lifx.frameaddr", "Frame Address")
    local PROTOCOL_HEADER = Proto("lifx.protoheader", "Protocol Header")
    local PAYLOAD = Proto("lifx.payload", "Payload")

    -- Device Messages
    local STATE_SERVICE = Proto("lifx.stateservice", "State Service")
    local STATE_HOST_INFO = Proto("lifx.statehostinfo", "State Host Info")
    local STATE_HOST_FIRMWARE = Proto("lifx.statehostfirmware", "State Host Firmware")
    local STATE_WIFI_INFO = Proto("lifx.statewifiinfo", "State Wifi Info")
    local STATE_WIFI_FIRMWARE = Proto("lifx.statewififirmware", "State Wifi Firmware")
    local SET_DEVICE_POWER = Proto("lifx.setdevicepower", "Set Device Power")
    local STATE_DEVICE_POWER = Proto("lifx.statedevicepower", "State Device Power")
    local SET_LABEL = Proto("lifx.setlabel", "Set Label")
    local STATE_LABEL = Proto("lifx.statelabel", "State Label")
    local STATE_VERSION = Proto("lifx.stateversion", "State Version")
    local STATE_INFO = Proto("lifx.stateinfo", "State Info")
    local SET_LOCATION = Proto("lifx.setlocation", "Set Location")
    local STATE_LOCATION = Proto("lifx.statelocation", "State Location")
    local SET_GROUP = Proto("lifx.setgroup", "Set Group")
    local STATE_GROUP = Proto("lifx.stategroup", "State Group")
    local ECHO_REQUEST = Proto("lifx.echorequest", "Echo Request")
    local ECHO_RESPONSE = Proto("lifx.echoresponse", "Echo Response")

    -- Data Types
    local COLOR = Proto("lifx.color", "Color")
    local TILE = Proto("lifx.tile", "Tile")

    -- Light Messages
    local SET_COLOR = Proto("lifx.setcolor", "Set Color")
    local SET_WAVEFORM = Proto("lifx.setwaveform", "Set Waveform")
    local SET_WAVEFORM_OPTIONAL = Proto("lifx.setwaveformoptional", "Set Waveform Optional")
    local STATE = Proto("lifx.state", "State")
    local SET_LIGHT_POWER = Proto("lifx.setlightpower", "Set Light Power")
    local STATE_LIGHT_POWER = Proto("lifx.statelightpower", "State Light Power")
    local STATE_INFRARED = Proto("lifx.stateinfrared", "State Infrared")
    local SET_INFRARED = Proto("lifx.setinfrared", "Set Infrared")

    -- MultiZone Messages
    local SET_COLOR_ZONES = Proto("lifx.setcolorzones", "Set Color Zones")
    local GET_COLOR_ZONES = Proto("lifx.getcolorzones", "Get Color Zones")
    local STATE_ZONE = Proto("lifx.statezone", "State Zone")
    local STATE_MULTI_ZONE = Proto("lifx.statemultizone", "State Multi Zone")
    local SET_MOVE_EFFECT = Proto("lifx.setmoveeffect", "Set Move Effect")
    local STATE_MOVE_EFFECT = Proto("lifx.statemoveeffect", "State Move Effect")

    -- Tile Messages
    local GET_DEVICE_CHAIN = Proto("lifx.getdevicechain", "Get Device Chain")
    local STATE_DEVICE_CHAIN = Proto("lifx.statedevicechain", "State Device Chain")
    local SET_USER_POSITION = Proto("lifx.setuserposition", "Set User Position")
    local GET_TILE_STATE64 = Proto("lifx.gettilestate64", "Get Tile State 64")
    local STATE_TILE_STATE64 = Proto("lifx.statetilestate64", "State Tile State 64")
    local SET_TILE_STATE64 = Proto("lifx.settilestate64", "Set Tile State 64")

    
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
                         [507] = "getMoveEffect", [508] = "setMoveEffect", [509] = "stateMoveEffect", [702] = "stateDeviceChain", [703] = "setUserPosition",
                         [707] = "getTileState", [711] = "stateTileState", [715] = "setTileState"}

    local ph = PROTOCOL_HEADER.fields
    ph.reservedTwo = ProtoField.uint64("lifx.reserved2", "Reserved2", base.DEC, nil, nil, "Reserved.")
    ph.type = ProtoField.uint16("lifx.type", "Type", base.DEC, messageTypes, nil, "Message type determines the payload being used.")
    ph.reservedThree = ProtoField.uint16("lifx.reserved3", "Reserved3", base.DEC, nil, nil, "Reserved.")

    local pl = PAYLOAD.fields
    pl.data = ProtoField.bytes("lifx.data", "Data", nil, "The data of the packet payload.")

    local products = {[1] = "Original 1000", [3] = "Color 650", [10] = "White 800 (Low Voltage)", [11] = "White 800 (High Voltage)",
                     [18] = "White 900 BR30 (Low Voltage)", [20] = "Color 1000 BR30", [22] = "Color 1000", [27] = "LIFX A19", [28] = "LIFX BR30",
                     [29] = "LIFX+ A19", [30] = "LIFX+ BR30", [31] = "LIFX Z", [32] = "LIFX Z 2", [36] = "LIFX Downlight", [37] = "LIFX Downlight",
                     [38] = "LIFX Beam", [43] = "LIFX A19", [44] = "LIFX BR30", [45] = "LIFX+ A19", [46] = "LIFX+ BR30", [49] = "LIFX Mini",
                     [50] = "LIFX Mini Day and Dusk", [51] = "LIFX Mini White", [52] = "LIFX GU10", [55] = "LIFX Tile", [59] = "LIFX Mini Color",
                     [60] = "LIFX Mini Day and Dusk", [61] = "LIFX Mini White"}

    local c = COLOR.fields
    c.hue = ProtoField.uint16("lifx.hue", "Hue", base.DEC, nil, nil, "Hue: range 0 to 65535")
    c.sat = ProtoField.uint16("lifx.sat", "Saturation", base.DEC, nil, nil, "Saturation: range 0 to 65535")
    c.bri = ProtoField.uint16("lifx.bri", "Brightness", base.DEC, nil, nil, "Brightness: range 0 to 65535")
    c.kel = ProtoField.uint16("lifx.kel", "Kelvin", base.DEC, nil, nil, "Kelvin: range 2500° (warm) to 9000° (cool)")

    -- PAYLOAD protocol fields
    local ss = STATE_SERVICE.fields
    ss.service = ProtoField.uint8("lifx.service", "Service", base.DEC, nil, nil, "1 = UDP.")
    ss.port = ProtoField.uint32("lifx.port", "Port", base.DEC, nil, nil, "The IP port number used by a LIFX device for a specific Service.")

    local shi = STATE_HOST_INFO.fields
    shi.signal = ProtoField.float("lifx.host.signal", "Signal", nil, "Radio receive signal strength in milliWatts.")
    shi.tx = ProtoField.uint32("lifx.host.tx", "Bytes Transmitted", base.DEC, nil, nil, "Bytes transmitted since power on.")
    shi.rx = ProtoField.uint32("lifx.host.rx", "Bytes Received", base.DEC, nil, nil, "Bytes received since power on.")
    shi.reserved = ProtoField.int16("lifx.reserved4", "Reserved", base.DEC)

    local shf = STATE_HOST_FIRMWARE.fields
    shf.build = ProtoField.uint64("lifx.host.build", "Build", base.DEC, nil, nil, "Firmware build time (absolute time in nanoseconds since epoch).")
    shf.reserved = ProtoField.uint64("lifx.reserved5", "Reserved", base.HEX)
    shf.version = ProtoField.uint32("lifx.host.version", "Version", base.DEC, nil, nil, "Firmware version.")

    local swi = STATE_WIFI_INFO.fields
    swi.signal = ProtoField.float("lifx.wifi.signal", "Signal", nil, "Radio receive signal strength in milliWatts.")
    swi.tx = ProtoField.uint32("lifx.wifi.tx", "Bytes Transmitted", base.DEC, nil, nil, "Bytes transmitted since power on.")
    swi.rx = ProtoField.uint32("lifx.wifi.rx", "Bytes Received", base.DEC, nil, nil, "Bytes received since power on.")
    swi.reserved = ProtoField.int16("lifx.reserved6", "Reserved", base.DEC)

    local swf = STATE_WIFI_FIRMWARE.fields
    swf.build = ProtoField.uint64("lifx.wifi.build", "Build", base.DEC, nil, nil, "Firmware build time (absolute time in nanoseconds since epoch).")
    swf.reserved = ProtoField.uint64("lifx.reserved7", "Reserved", base.HEX)
    swf.version = ProtoField.uint32("lifx.wifi.version", "Version", base.DEC, nil, nil, "Firmware version.")

    local powerTable = {[0] = "OFF", [65535] = "ON"}
    local setdp = SET_DEVICE_POWER.fields
    setdp.level = ProtoField.uint16("lifx.device.setPower", "Set Device Power Level", base.DEC, powerTable, nil, "The power level can be either standby (0) or enabled (65535).")
    
    local sdp = STATE_DEVICE_POWER.fields
    sdp.level = ProtoField.uint16("lifx.device.statePower", "State Device Power Level", base.DEC, powerTable, nil, "The power level can be either standby (0) or enabled (65535).")

    local setl = SET_LABEL.fields
    setl.label = ProtoField.string("lifx.setLabel", "Set Label", nil, "For user interfaces purposes, each device can be identified by their label.")

    local sl = STATE_LABEL.fields
    sl.label = ProtoField.string("lifx.stateLabel", "State Label", nil, "For user interfaces purposes, each device can be identified by their label.")

    local sv = STATE_VERSION.fields
    sv.vendor = ProtoField.uint32("lifx.vendor", "Vendor ID", base.DEC)
    sv.product = ProtoField.uint32("lifx.product", "Product ID", base.DEC, products)
    sv.version = ProtoField.uint32("lifx.version", "Hardware Version", base.DEC)

    local si = STATE_INFO.fields
    si.time = ProtoField.uint64("lifx.time", "Time", base.DEC, nil, nil, "Current time (absolute time in nanoseconds since epoch).")
    si.uptime = ProtoField.uint64("lifx.uptime", "Uptime", base.DEC, nil, nil, "Time since last power on (relative time in nanoseconds).")
    si.downtime = ProtoField.uint64("lifx.downtime", "Downtime", base.DEC, nil, nil, "Last power off period, 5 second accuracy (in nanoseconds).")

    local setloc = SET_LOCATION.fields
    setloc.location = ProtoField.guid("lifx.setLocation", "Location", "guid byte array.")
    setloc.label = ProtoField.string("lifx.setLocationLabel", "Location Label", nil, "Text label for location.")
    setloc.updatedAt = ProtoField.uint64("lifx.setLocationUpdatedAt", "Updated At", base.DEC, nil, nil, "UTC timestamp of last label update in nanoseconds.")

    local stateloc = STATE_LOCATION.fields
    stateloc.location = ProtoField.guid("lifx.location", "Location", "guid byte array.")
    stateloc.label = ProtoField.string("lifx.locationLabel", "Location Label", nil, "Text label for location.")
    stateloc.updatedAt = ProtoField.uint64("lifx.locationUpdatedAt", "Updated At", base.DEC, nil, nil, "UTC timestamp of last label update in nanoseconds.")

    local setGro = SET_GROUP.fields 
    setGro.group = ProtoField.guid("lifx.setGroup", "Group", "guid byte array.")
    setGro.label = ProtoField.string("lifx.setGroupLabel", "Group Label", nil, "Text label for group.")
    setGro.updatedAt = ProtoField.uint64("lifx.setGroupUpdatedAt", "Updated At", base.DEC, nil, nil, "UTC timestamp of last label update in nanoseconds.")

    local stateGro = STATE_GROUP.fields
    stateGro.group = ProtoField.guid("lifx.group", "Location", "guid byte array.")
    stateGro.label = ProtoField.string("lifx.groupLabel", "Location Label", nil, "Text label for group.")
    stateGro.updatedAt = ProtoField.uint64("lifx.groupUpdatedAt", "Updated At", base.DEC, nil, nil, "UTC timestamp of last label update in nanoseconds.")

    local echoReq = ECHO_REQUEST.fields
    echoReq.echo = ProtoField.bytes("lifx.echoReq", "Echo Request", "An arbitrary payload to be echoed back.")

    local echoRes = ECHO_RESPONSE.fields
    echoRes.echo = ProtoField.bytes("lifx.echoRes", "Echo Response", "An arbitrary payload echoed back.")

    local setCol = SET_COLOR.fields
    setCol.reserved = ProtoField.uint8("lifx.reserved8", "Reserved")
    setCol.color = ProtoField.protocol("lifx.setColor", "Color", nil, "Color in HSBK.")
    setCol.duration = ProtoField.uint32("lifx.setDuration", "Duration", base.DEC, nil, nil, "Color transition time in milliseconds.")

    local waveforms = {[0] = "Saw", [1] = "Sine", [2] = "Half Sine", [3] = "Triangle", [4] = "Pulse"}
    
    local setWave = SET_WAVEFORM.fields
    setWave.reserved = ProtoField.uint8("lifx.reserved9", "Reserved")
    setWave.transient = ProtoField.bool("lifx.transient", "Transient", 8, nil, 0x1, "Whether or not color does persist.")
    setWave.color = ProtoField.protocol("lifx.waveColor", "Color", nil, "End color in HSBK.")
    setWave.period = ProtoField.uint32("lifx.period", "Period", base.DEC, nil, nil, "The duration of a cycle in milliseconds.")
    setWave.cycles = ProtoField.float("lifx.cycles", "Cycles", nil, "Number of Cycles.")
    setWave.skewRatio = ProtoField.int16("lifx.skew", "Skew Ratio", base.DEV, nil, nil, "Waveform Skew, [-32768, 32767] scaled to [0, 1].")
    setWave.waveform = ProtoField.uint8("lifx.waveform", "Waveform", base.DEC, waveforms, nil, "Waveform to use for transition.")

    local setWaveOpt = SET_WAVEFORM_OPTIONAL.fields
    setWaveOpt.reserved = ProtoField.uint8("lifx.reserved10", "Reserved")
    setWaveOpt.transient = ProtoField.bool("lifx.transientOpt", "Transient", 8, nil, 0x1, "Whether or not color does persist.")
    setWaveOpt.color = ProtoField.protocol("lifx.waveColorOpt", "Color", nil, "End color in HSBK.")
    setWaveOpt.period = ProtoField.uint32("lifx.periodOpt", "Period", base.DEC, nil, nil, "The duration of a cycle in milliseconds.")
    setWaveOpt.cycles = ProtoField.float("lifx.cyclesOpt", "Cycles", nil, "Number of Cycles.")
    setWaveOpt.skewRatio = ProtoField.int16("lifx.skewOpt", "Skew Ratio", base.DEV, nil, nil, "Waveform Skew, [-32768, 32767] scaled to [0, 1].")
    setWaveOpt.waveform = ProtoField.uint8("lifx.waveformOpt", "Waveform", base.DEC, waveforms, nil, "Waveform to use for transition.")
    setWaveOpt.setHue = ProtoField.bool("lifx.setHueOpt", "Set Hue", 8, nil, 0x1, "Set the Hue or not.")
    setWaveOpt.setSat = ProtoField.bool("lifx.setSatOpt", "Set Saturation", 8, nil, 0x1, "Set the Saturation or not.")
    setWaveOpt.setBri = ProtoField.bool("lifx.setBriOpt", "Set Brightness", 8, nil, 0x1, "Set the Brightness or not.")
    setWaveOpt.setKel = ProtoField.bool("lifx.setKelOpt", "Set Kelvin", 8, nil, 0x1, "Set the Kelvin or not.")

    local stte = STATE.fields
    stte.color = ProtoField.protocol("lifx.state.color", "Color", nil, "Color in HSBK.")
    stte.reserved = ProtoField.int16("lifx.reserved11", "Reserved")
    stte.power = ProtoField.uint16("lifx.state.power", "State Device Power Level", base.DEC, powerTable, nil, "The power level can be either standby (0) or enabled (65535).")
    stte.label = ProtoField.string("lifx.state.label", "State Label", nil, "For user interfaces purposes, each device can be identified by their label.")
    stte.reserved2 = ProtoField.uint64("lifx.reserved12", "Reserved")

    local setLiPow = SET_LIGHT_POWER.fields
    setLiPow.level = ProtoField.uint16("lifx.light.setPower", "Set Light Power Level", base.DEC, powerTable, nil, "The power level can be either standby (0) or enabled (65535).")
    setLiPow.duration = ProtoField.uint32("lifx.light.setDuration", "Transition Time", base.DEC, nil, nil, "The duration is the power level transition time in milliseconds.")

    local stateLiPow = STATE_LIGHT_POWER.fields
    stateLiPow.level = ProtoField.uint16("lifx.light.power", "Light Power Level", base.DEC, powerTable, nil, "The power level can be either standby (0) or enabled (65535).")

    local stateInfra = STATE_INFRARED.fields
    stateInfra.level = ProtoField.uint16("lifx.infra.power", "Infrared Brighness Level", base.DEC, nil, nil, "The current maximum setting for the infrared channel.")

    local setInfra = SET_INFRARED.fields
    setInfra.level = ProtoField.uint16("lifx.infra.setPower", "Infrared Brighness Level", base.DEC, nil, nil, "The maximum setting for the infrared channel.")

    -- MultiZone Payloads
    local apply = {[0] = "No Apply", [1] = "Apply", [2] = "Apply Only"}

    local setColZone = SET_COLOR_ZONES.fields
    setColZone.startIndex = ProtoField.uint8("lifx.setColZone.start", "Start Index", base.DEC, nil, nil, "Start index from which to set the color.")
    setColZone.endIndex = ProtoField.uint8("lifx.setColZone.end", "End Index", base.DEC, nil, nil, "End index to which to set the color.")
    setColZone.color = ProtoField.protocol("lifx.setColZone.color", "Color", nil, "Color in HSBK.")
    setColZone.duration = ProtoField.uint32("lifx.setColZone.duration", "Transition Time", base.DEC, nil, nil, "The duration is the power level transition time in milliseconds.")
    setColZone.apply = ProtoField.uint8("lifx.setColZone.apply", "Apply", base.DEC, apply, nil, "NO_APPLY (0) = Don't apply the requested changes until a message with APPLY or APPLY_ONLY is sent. APPLY (1) = Apply the changes immediately and apply any pending changes. APPLY_ONLY (2) Ignore the requested changes in this message and only apply pending changes.")

    local getColZone = GET_COLOR_ZONES.fields
    getColZone.startIndex = ProtoField.uint8("lifx.getColZone.start", "Start Index", base.DEC, nil, nil, "Start index from which to set the color.")
    getColZone.endIndex = ProtoField.uint8("lifx.getColZone.end", "End Index", base.DEC, nil, nil, "End index to which to set the color.")

    local stteZone = STATE_ZONE.fields
    stteZone.count = ProtoField.uint8("lifx.stateZone.count", "Count", base.DEC, nil, nil, "Contains the count of the total number of zones available on the device.")
    stteZone.index = ProtoField.uint8("lifx.stateZone.index", "Index", base.DEC, nil, nil, "Indicates which zone is represented.")
    stteZone.color = ProtoField.protocol("lifx.stateZone.color", "Color", nil, "Color in HSBK.")

    local stteMultiZone = STATE_MULTI_ZONE.fields
    stteMultiZone.count = ProtoField.uint8("lifx.stateMultiZone.count", "Count", base.DEC, nil, nil, "Contains the count of the total number of zones available on the device.")
    stteMultiZone.index = ProtoField.uint8("lifx.stateMultiZone.index", "Index", base.DEC, nil, nil, "Indicates which zone is represented.")
    stteMultiZone.colors = ProtoField.protocol("lifx.stateMultiZone.color", "Colors", nil, "Colors in HSBK.")

    -- Tile Payloads
    local tle = TILE.fields
    tle.reserved1 = ProtoField.int16("lifx.tile.res1", "Reserved 1", base.DEC)
    tle.reserved2 = ProtoField.int16("lifx.tile.res2", "Reserved 2", base.DEC)
    tle.reserved3 = ProtoField.int16("lifx.tile.res3", "Reserved 3", base.DEC)
    tle.reserved4 = ProtoField.int16("lifx.tile.res4", "Reserved 4", base.DEC)
    tle.userX = ProtoField.float("lifx.tile.userx", "User X", nil, "The x-position of each tile")
    tle.usery = ProtoField.float("lifx.tile.usery", "User Y", nil, "The y-position of each tile")
    tle.width = ProtoField.uint8("lifx.tile.width", "Width", base.DEC, nil, nil, "The number of pixels that are on the x-axis of the tile.")
    tle.height = ProtoField.uint8("lifx.tile.heigth", "Height", base.DEC, nil, nil, "The number of pixels that are on the y-axis of the tile.")
    tle.reserved5 = ProtoField.uint8("lifx.tile.res5", "Reserved 5", base.DEC)
    tle.deviceVersionVendor = ProtoField.uint32("lifx.tile.vendor", "Vendor ID", base.DEC)
    tle.deviceVersionProduct = ProtoField.uint32("lifx.tile.product", "Product ID", base.DEC, products)
    tle.deviceVersionVersion = ProtoField.uint32("lifx.tile.version", "Hardware Version", base.DEC)
    tle.firmwareBuild = ProtoField.uint64("lifx.tile.fwbuild", "Firmware Build", base.DEC)
    tle.reserved6 = ProtoField.uint64("lifx.tile.res6", "Reserved 6", base.DEC)
    tle.firmwareVersion = ProtoField.uint32("lifx.tile.fwversion", "Firmware Version", base.DEC)
    tle.reserved7 = ProtoField.uint32("lifx.tile.res7", "Reserved 7", base.DEC)

    local stteDevChain = STATE_DEVICE_CHAIN.fields
    stteDevChain.startIndex = ProtoField.uint8("lifx.stateDeviceChain.start", "Start Index", base.DEC, nil, nil, "Start index of the first of the 16 Tiles.")
    stteDevChain.totalCount = ProtoField.uint8("lifx.stateDeviceChain.total", "Total Count", base.DEC, nil, nil, "The overall count of Tiles in this chain.")
    stteDevChain.tiles = ProtoField.protocol("lifx.stateDeviceChain.tiles", "Tiles")

    local setUserPos = SET_USER_POSITION.fields
    setUserPos.tileIndex = ProtoField.uint8("lifx.setUserPosition.index", "Tile Index", base.DEC, nil, nil, "The index of the Tile.")
    setUserPos.reserved = ProtoField.int16("lifx.setUserPosition.res", "Reserved", base.DEC)
    setUserPos.userX = ProtoField.float("lifx.setUserPosition.userx", "User X", nil, "The x-position of the tile")
    setUserPos.userY = ProtoField.float("lifx.setUserPosition.usery", "User Y", nil, "The y-position of the tile")

    local getTileStte = GET_TILE_STATE64.fields
    getTileStte.tileIndex = ProtoField.uint8("lifx.getTileState.index", "Tile Index", base.DEC, nil, nil, "Used to control the starting tile in the chain.")
    getTileStte.length = ProtoField.uint8("lifx.getTileState.length", "Length", base.DEC, nil, nil, "Used to get the state of that many tiles beginning from the tile_index.")
    getTileStte.reserved = ProtoField.uint8("lifx.getTileState.res", "Reserved", base.DEC)
    getTileStte.x = ProtoField.uint8("lifx.getTileState.x", "X-Position", base.DEC)
    getTileStte.y = ProtoField.uint8("lifx.getTileState.y", "Y-Position", base.DEC)
    getTileStte.width = ProtoField.uint8("lifx.getTileState.width", "Width", base.DEC)

    local stteTileState = STATE_TILE_STATE64.fields
    stteTileState.tileIndex = ProtoField.uint8("lifx.stateTileState.index", "Tile Index", base.DEC)
    stteTileState.reserved = ProtoField.uint8("lifx.stateTileState.res", "Reserved", base.DEC)
    stteTileState.x = ProtoField.uint8("lifx.stateTileState.x", "X-Position", base.DEC)
    stteTileState.y = ProtoField.uint8("lifx.stateTileState.y", "Y-Position", base.DEC)
    stteTileState.width = ProtoField.uint8("lifx.stateTileState.width", "Width", base.DEC)
    stteTileState.colors = ProtoField.protocol("lifx.stateTileState.colors", "Colors", nil, "Colors in HSBK.")

    local setTileStte = SET_TILE_STATE64.fields
    setTileStte.tileIndex = ProtoField.uint8("lifx.setTileState.index", "Tile Index", base.DEC, nil, nil, "Used to control the starting tile in the chain.")
    setTileStte.length = ProtoField.uint8("lifx.setTileState.length", "Length", base.DEC)
    setTileStte.reserved = ProtoField.uint8("lifx.setTileState.res", "Reserved", base.DEC)
    setTileStte.x = ProtoField.uint8("lifx.setTileState.x", "X-Position", base.DEC)
    setTileStte.y = ProtoField.uint8("lifx.setTileState.y", "Y-Position", base.DEC)
    setTileStte.width = ProtoField.uint8("lifx.setTileState.width", "Width", base.DEC)
    setTileStte.colors = ProtoField.protocol("lifx.setTileState.colors", "Colors", nil, "Colors in HSBK.")


    -- parser functions
    function stateService(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_SERVICE, tvbuffer())
        payload:add_le(ss.service, tvbuffer(offset, 1))
        offset = offset + 1
        
        payload:add_le(ss.port, tvbuffer(offset, 4))
    end
        
    function stateHostInfo(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_HOST_INFO, tvbuffer())
        payload:add_le(shi.signal, tvbuffer(offset, 4))
        offset = offset + 4
        
        payload:add_le(shi.tx, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(shi.rx, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(shi.reserved, tvbuffer(offset, 2))
    end

    function stateHostFirmware(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_HOST_FIRMWARE, tvbuffer())
        payload:add_le(shf.build, tvbuffer(offset, 8))
        offset = offset + 8

        payload:add_le(shf.reserved, tvbuffer(offset, 8))
        offset = offset + 8
        
        payload:add_le(shf.version, tvbuffer(offset, 4))
    end

    function stateWifiInfo(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_WIFI_INFO, tvbuffer())
        payload:add_le(swi.signal, tvbuffer(offset, 4))
        offset = offset + 4
        
        payload:add_le(swi.tx, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(swi.rx, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(swi.reserved, tvbuffer(offset, 2))
    end

    function stateWifiFirmware(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_WIFI_FIRMWARE, tvbuffer())

        payload:add_le(swf.build, tvbuffer(offset, 8))
        offset = offset + 8

        payload:add_le(swf.reserved, tvbuffer(offset, 8))
        offset = offset + 8
        
        payload:add_le(swf.version, tvbuffer(offset, 4))
    end

    function setDevicePower(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(SET_DEVICE_POWER, tvbuffer())
        payload:add_le(setdp.level, tvbuffer(0, 2))
    end

    function stateDevicePower(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(STATE_DEVICE_POWER, tvbuffer())
        payload:add_le(sdp.level, tvbuffer(0, 2))
    end

    function setLabel(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(SET_LABEL, tvbuffer())
        payload:add_le(setl.label, tvbuffer(0, 32))
    end

    function stateLabel(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(STATE_LABEL, tvbuffer())
        payload:add_le(sl.label, tvbuffer(0, 32))
    end

    function stateVersion(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_VERSION, tvbuffer())

        payload:add_le(sv.vendor, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(sv.product, tvbuffer(offset, 4))
        offset = offset + 4
        
        payload:add_le(sv.version, tvbuffer(offset, 4))
    end

    function stateInfo(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_INFO, tvbuffer())

        payload:add_le(si.time, tvbuffer(offset, 8))
        offset = offset + 8

        payload:add_le(si.uptime, tvbuffer(offset, 8))
        offset = offset + 8
        
        payload:add_le(si.downtime, tvbuffer(offset, 8))
    end

    function setLocation(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_LOCATION, tvbuffer())

        payload:add_le(setloc.location, tvbuffer(offset, 16))
        offset = offset + 16

        payload:add_le(setloc.label, tvbuffer(offset, 32))
        offset = offset + 32
        
        payload:add_le(setloc.updatedAt, tvbuffer(offset, 8))
    end

    function stateLocation(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_LOCATION, tvbuffer())

        payload:add_le(stateloc.location, tvbuffer(offset, 16))
        offset = offset + 16

        payload:add_le(stateloc.label, tvbuffer(offset, 32))
        offset = offset + 32
        
        payload:add_le(stateloc.updatedAt, tvbuffer(offset, 8))
    end

    function setGroup(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_GROUP, tvbuffer())

        payload:add_le(setGro.group, tvbuffer(offset, 16))
        offset = offset + 16

        payload:add_le(setGro.label, tvbuffer(offset, 32))
        offset = offset + 32
        
        payload:add_le(setGro.updatedAt, tvbuffer(offset, 8))
    end

    function stateGroup(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_GROUP, tvbuffer())

        payload:add_le(stateGro.group, tvbuffer(offset, 16))
        offset = offset + 16

        payload:add_le(stateGro.label, tvbuffer(offset, 32))
        offset = offset + 32
        
        payload:add_le(stateGro.updatedAt, tvbuffer(offset, 8))
    end

    function echoRequest(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(ECHO_REQUEST, tvbuffer())

        payload:add_le(echoReq.echo, tvbuffer(0, 64))
    end

    function echoResponse(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(ECHO_RESPONSE, tvbuffer())

        payload:add_le(echoRes.echo, tvbuffer(0, 64))
    end

    function colorTreeItem(hsbk, tvbuffer)
        local offset = 0

        local hueItem = hsbk:add_le(c.hue, tvbuffer(offset, 2))
        local hueVal = math.floor((tvbuffer(offset, 2):le_uint() * 360 / 65535)  + 0.5)
        hueItem:append_text(" (" .. hueVal .. "°)")
        offset = offset + 2

        local satItem = hsbk:add_le(c.sat, tvbuffer(offset, 2))
        local satVal = math.floor((tvbuffer(offset, 2):le_uint() * 100 / 65535)  + 0.5)
        satItem:append_text(" (" .. satVal .. "%)")
        offset = offset + 2

        local briItem = hsbk:add_le(c.bri, tvbuffer(offset, 2))
        local briVal = math.floor((tvbuffer(offset, 2):le_uint() * 100 / 65535)  + 0.5)
        briItem:append_text(" (" .. briVal .. "%)")
        offset = offset + 2

        local kelItem = hsbk:add_le(c.kel, tvbuffer(offset, 2))
        local kelVal = tvbuffer(offset, 2):le_uint()
        kelItem:append_text(" (" .. kelVal .. "°)")
    end

    function setColor(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_COLOR, tvbuffer())

        payload:add_le(setCol.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8        
        
        local durItem = payload:add_le(setCol.duration, tvbuffer(offset, 4))
        durItem:append_text("ms")
    end

    function setWaveform(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_WAVEFORM, tvbuffer())

        payload:add_le(setWave.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWave.transient, tvbuffer(offset, 1))
        offset = offset + 1

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8   

        local perItem = payload:add_le(setWave.period, tvbuffer(offset, 4))
        perItem:append_text("ms")
        offset = offset + 4

        payload:add_le(setWave.cycles, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(setWave.skewRatio, tvbuffer(offset, 2))
        offset = offset + 2

        payload:add_le(setWave.waveform, tvbuffer(offset, 1))
        offset = offset + 1
    end

    function setWaveformOptional(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_WAVEFORM_OPTIONAL, tvbuffer())

        payload:add_le(setWaveOpt.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWaveOpt.transient, tvbuffer(offset, 1))
        offset = offset + 1

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8   

        local perItem = payload:add_le(setWaveOpt.period, tvbuffer(offset, 4))
        perItem:append_text("ms")
        offset = offset + 4

        payload:add_le(setWaveOpt.cycles, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(setWaveOpt.skewRatio, tvbuffer(offset, 2))
        offset = offset + 2

        payload:add_le(setWaveOpt.waveform, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWaveOpt.setHue, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWaveOpt.setSat, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWaveOpt.setBri, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setWaveOpt.setKel, tvbuffer(offset, 1))
        offset = offset + 1

    end

    function state(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE, tvbuffer())

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8

        payload:add_le(stte.reserved, tvbuffer(offset, 2))
        offset = offset + 2

        payload:add_le(stte.power, tvbuffer(offset, 2))
        offset = offset + 2

        payload:add_le(stte.label, tvbuffer(offset, 32))
        offset = offset + 32

        payload:add_le(stte.reserved2, tvbuffer(offset, 8))
        offset = offset + 8

    end

    function setLightPower(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_LIGHT_POWER, tvbuffer())
        
        payload:add_le(setLiPow.level, tvbuffer(offset, 2))
        offset = offset + 2

        local durItem = payload:add_le(setLiPow.duration, tvbuffer(offset, 4))
        durItem:append_text("ms")

    end

    function stateLightPower(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(STATE_LIGHT_POWER, tvbuffer())
        payload:add_le(stateLiPow.level, tvbuffer(0, 2))
    end
    
    function stateInfrared(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(STATE_INFRARED, tvbuffer())
        payload:add_le(stateInfra.level, tvbuffer(0, 2))
    end

    function setInfrared(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(SET_INFRARED, tvbuffer())
        payload:add_le(setInfra.level, tvbuffer(0, 2))
    end
    
    function setColorZones(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_COLOR_ZONES, tvbuffer())

        payload:add_le(setColZone.startIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setColZone.endIndex, tvbuffer(offset, 1))
        offset = offset + 1

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8

        payload:add_le(setColZone.duration, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(setColZone.apply, tvbuffer(offset, 1))
    end

    function getColorZones(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(GET_COLOR_ZONES, tvbuffer())

        payload:add_le(getColZone.startIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getColZone.endIndex, tvbuffer(offset, 1))
    end

    function stateZone(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_ZONE, tvbuffer())

        payload:add_le(stteZone.count, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteZone.index, tvbuffer(offset, 1))
        offset = offset + 1

        local hsbk = payload:add(COLOR, tvbuffer(offset, 8))
        colorTreeItem(hsbk, tvbuffer(offset, 8))
        offset = offset + 8
    end

    function stateMultiZone(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_MULTI_ZONE, tvbuffer())

        payload:add_le(stteMultiZone.count, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteMultiZone.index, tvbuffer(offset, 1))
        offset = offset + 1

        local colors = payload:add(stteMultiZone.colors, tvbuffer(offset))

        for i=0,7,1
        do
            local colortree = colors:add(COLOR, tvbuffer(offset, 8))
            colortree:append_text(i)
            colorTreeItem(colortree, tvbuffer(offset, 8))
            offset = offset + 8
        end
    end

    function setMoveEffect(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(PAYLOAD, tvbuffer())
        payload:add(pl.data, tvbuffer())
    end

    function stateMoveEffect(tvbuffer, subtreeitem)
        local payload = subtreeitem:add(PAYLOAD, tvbuffer())
        payload:add(pl.data, tvbuffer())
    end 

    -- Tiles
    function tileTreeItem(tile, tvbuffer)
        local offset = 0

        tile:add_le(tle.reserved1, tvbuffer(offset, 2))
        offset = offset + 2
        
        tile:add_le(tle.reserved2, tvbuffer(offset, 2))
        offset = offset + 2
        
        tile:add_le(tle.reserved3, tvbuffer(offset, 2))
        offset = offset + 2
        
        tile:add_le(tle.reserved4, tvbuffer(offset, 2))
        offset = offset + 2

        tile:add_le(tle.userX, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.userY, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.width, tvbuffer(offset, 1))
        offset = offset + 1

        tile:add_le(tle.height, tvbuffer(offset, 1))
        offset = offset + 1

        tile:add_le(tle.reserved5, tvbuffer(offset, 1))
        offset = offset + 1

        tile:add_le(tle.deviceVersionVendor, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.deviceVersionProduct, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.deviceVersionVersion, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.firmwareBuild, tvbuffer(offset, 8))
        offset = offset + 8

        tile:add_le(tle.reserved6, tvbuffer(offset, 8))
        offset = offset + 8

        tile:add_le(tle.firmwareVersion, tvbuffer(offset, 4))
        offset = offset + 4

        tile:add_le(tle.reserved7, tvbuffer(offset, 4))
        offset = offset + 4
    end
    
    function stateDeviceChain(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_DEVICE_CHAIN, tvbuffer())

        payload:add_le(stteDevChain.startIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteDevChain.totalCount, tvbuffer(offset, 1))
        offset = offset + 1

        local tiles = payload:add(stteDevChain.tiles, tvbuffer(offset))

        for i=0,15,1
        do
            local tiletree = tiles:add(TILE, tvbuffer(offset, 55))
            tiletree:append_text(i)
            tileTreeItem(tiletree, tvbuffer(offset, 55))
            offset = offset + 55
        end

    function setUserPosition(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_USER_POSITION, tvbuffer())

        payload:add_le(setUserPos.tileIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setUserPos.reserved, tvbuffer(offset, 2))
        offset = offset + 2

        payload:add_le(setUserPos.userX, tvbuffer(offset, 4))
        offset = offset + 4

        payload:add_le(setUserPos.userY, tvbuffer(offset, 4))
    end

    function getTileState(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(GET_TILE_STATE64, tvbuffer())

        payload:add_le(getTileStte.tileIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getTileStte.length, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getTileStte.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getTileStte.x, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getTileStte.y, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(getTileStte.width, tvbuffer(offset, 1))
    end

    function stateTileState(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(STATE_TILE_STATE64, tvbuffer())

        payload:add_le(stteTileState.tileIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteTileState.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteTileState.x, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteTileState.y, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(stteTileState.width, tvbuffer(offset, 1))
        offset = offset + 1

        local colors = payload:add(stteTileState.colors, tvbuffer(offset))
        for i=0,63,1
        do
            local colortree = colors:add(COLOR, tvbuffer(offset, 8))
            colortree:append_text(i)
            colorTreeItem(colortree, tvbuffer(offset, 8))
            offset = offset + 8
        end
    end

    function setTileState(tvbuffer, subtreeitem)
        local offset = 0
        local payload = subtreeitem:add(SET_TILE_STATE64, tvbuffer())

        payload:add_le(setTileStte.tileIndex, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setTileStte.length, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setTileStte.reserved, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setTileStte.x, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setTileStte.y, tvbuffer(offset, 1))
        offset = offset + 1

        payload:add_le(setTileStte.width, tvbuffer(offset, 1))
        offset = offset + 1

        local colors = payload:add(setTileStte.colors, tvbuffer(offset))
        for i=0,63,1
        do
            local colortree = colors:add(COLOR, tvbuffer(offset, 8))
            colortree:append_text(i)
            colorTreeItem(colortree, tvbuffer(offset, 8))
            offset = offset + 8
        end
    end
    
    -- message types that have payload
    local payloadFunctionTable = {[3] = stateService, [13] = stateHostInfo, [15] = stateHostFirmware, [17] = stateWifiInfo,
                        [19] = stateWifiFirmware, [21] = setDevicePower, [22] = stateDevicePower, [24] = setLabel,
                        [25] = stateLabel, [33] = stateVersion, [35] = stateInfo, [49] = setLocation, [50] = stateLocation,
                        [52] = setGroup, [53] = stateGroup, [58] = echoRequest, [59] = echoResponse, [102] = setColor,
                        [103] = setWaveform, [119] = setWaveformOptional, [107] = state, [117] = setLightPower,
                        [118] = stateLightPower, [121] = stateInfrared, [122] = setInfrared, [501] = setColorZones,
                        [502] = getColorZones, [503] = stateZone, [506] = stateMultiZone, [508] = setMoveEffect,
                        [509] = stateMoveEffect, [702] = stateDeviceChain, [703] = setUserPosition, [707] = getTileState,
                        [711] = stateTileState, [715] = setTileState}
                        

    local t = Field.new("lifx.type")
    
    -- DISSECTOR LOGIC IS HERE!

    function LIFX.dissector(tvbuffer, pinfo, treeitem)
            
        local subtreeitem = treeitem:add(LIFX, tvbuffer())
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
        
        protocol_header:add_le(ph.reservedThree, tvbuffer(offset, 2))
        offset = offset + 2
        
        -- Tree title append text
        local messageTypeValue = t().value
        local messageType = messageTypes[messageTypeValue]
        local messageTypeString
        if messageType then
            messageTypeString = "" .. messageType .. "(" .. messageTypeValue .. ")"
            local payloadFunction = payloadFunctionTable[messageTypeValue]
            if payloadFunction then
                local dataLength = tvbuffer:len() - offset
                payloadFunction(tvbuffer(offset, dataLength), subtreeitem)
            end
        else
            -- If message type is unknwon
            messageTypeString = messageTypeValue
            local dataLength = tvbuffer:len() - offset
            local payload = subtreeitem:add(PAYLOAD, tvbuffer(offset, dataLength))
            payload:add(pl.data, tvbuffer(offset, dataLength))
            offset = offset + dataLength
        end
        
        pinfo.cols.protocol = LIFX.name
        pinfo.cols.info = messageTypeString
        
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
ProtoField.guid(abbr, [name], [desc])

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
