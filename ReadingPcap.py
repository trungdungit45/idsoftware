import textwrap


# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr
def main():
	Age = b'\xF8\x08\x08\x08'
	print(get_mac_addr(Age).__str__())

main()
