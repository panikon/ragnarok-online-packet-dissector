# Ragnarok Online Packet Dissector
## LUA plugin for Wireshark

## How to install the plugin
* Copy the contents of [./plugin](/plugin) ([`ro_dissector.lua`](/plugin/ro_dissector.lua) and [`ro_packet_table.lua`](/plugin/ro_packet_table.lua)) and [./table/table_serialize.lua](/table/table_serialize.lua) to your Wireshark main directory
* Append `dofile('/ro_dissector.lua')` to the end of `init.lua`

## Updating Packet Table
```
lua update_packet.lua <in file>
```
* The in file structure should follow:
```
// packet <HEX header 0x%04x>
struct PACKET_<packet name with no spaces> {
  /* this+0x0 */ short PacketType
  /* this+0x2 */ short PacketLength
  ...
  /* this+<0x%04 pos> */ <C type> <variable name>
}
```

