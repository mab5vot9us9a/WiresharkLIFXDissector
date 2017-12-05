# WiresharkLIFXDissector
A [Wireshark](https://www.wireshark.org/) Plugin that dissects packets of the [LIFX LAN Protocol](https://lan.developer.lifx.com/docs/header-description). It looks at all packets that are sent over UDP port 56700 (the default port for LIFX lights).

I created this in part because I wanted an easy way to check my various implementations of the LIFX LAN Protocol and also because I was interested in learning a bit more about writing plugins for wireshark.

## Install
Install `lifx.lua` into the plugin directory of Wireshark.  


You can find the plugin directory by launching Wireshark and going to `Help > About > Folders`.

After copying the file, restart Wireshark.

## Filter Keys
The following is a list of all available filter keys provided by this plugin and their corresponding protocol fields.

### Protocol
`lifx` --> LIFX LAN API Protocol  

### Header Description  
`lifx.frame` --> Frame  
`lifx.frameAddr` --> Frame Address  
`lifx.protoHeader` --> Protocol Header  

### Frame
`lifx.size` --> Packet Size [*uint16*]  
`lifx.origin` --> Origin [*uint8*]  
`lifx.tagged` --> Tagged [*bool*]  
`lifx.addressable` --> Addressable [*bool*]  
`lifx.protocol` --> Protocol [*uint16*]  
`lifx.source` --> Source [*uint32*]  

### Frame Address
`lifx.target` --> Target [*ether*]  
`lifx.reservedOne` --> Reserved1 [*string*]  
`lifx.ack` --> ack\_required [*bool*]  
`lifx.res` --> res\_required [*bool*]  
`lifx.sequence` --> Sequence [*uint8*]  

### Protocol Header
`lifx.reservedTwo` --> Reserved2 [*uint64*]  
`lifx.type` --> Type [*uint16*]  
`lifx.reservedThree` --> Reserved3 [*uint16*]  

## License
GNU General Public License v3.0
