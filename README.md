# WiresharkLIFXDissector
A [Wireshark](https://www.wireshark.org/) Plugin that dissects packets of the [LIFX LAN Protocol](https://lan.developer.lifx.com/docs/header-description). It looks at all packets that are sent over UDP port 56700 (the default port for LIFX lights).

I created this in part because I wanted an easy way to check my various implementations of the LIFX LAN Protocol and also because I was interested in learning a bit more about writing plugins for wireshark.

## Install
Install `lifx.lua` into the plugin directory of Wireshark.  


You can find the plugin directory by launching Wireshark and going to `Help > About > Folders`.

After copying the file, restart Wireshark.

## License
GNU General Public License v3.0
