## packet-fanuc-hspo-r891
v0.1.4


## Overview

This is a (rather quick-and-dirty) Wireshark Lua dissector for the Fanuc High-Speed Position Output (R891) protocol.
For more information on the protocol, refer to the relevant Fanuc option documentation.


## Status

The dissector is mostly complete, except for the following:

 - no support for XML packets (ie: non-binary)
 - no support for packets with variables (ie: type 16)

This might change in future versions.


## Installation

### Linux

Copy or symlink the `packet-fanuc-hspo-r891.lua` file to either the Wireshark global (`/usr/(local/)share/wireshark/plugins`) or per-user (`$HOME/.config/wireshark/plugins` or `$HOME/.wireshark/plugins`) plugin directory.

### Windows

Copy or symlink the `packet-fanuc-hspo-r891.lua` file to either the Wireshark global (`%WIRESHARK%\plugins`) or per-user (`%APPDATA%\Wireshark\plugins`) plugin directory.


## Compatible Wireshark versions

The dissector has been extensively used with Wireshark versions 3.x, but is expected to work on most versions with Lua support.


## Disclaimer

The author of this software is not affiliated with FANUC Corporation in any way.
All trademarks and registered trademarks are property of their respective owners, and company, product and service names mentioned in this readme or appearing in source code or other artefacts in this repository are used for identification purposes only.
Use of these names does not imply endorsement by FANUC Corporation.
