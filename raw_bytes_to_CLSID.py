def guid_to_string(raw_bytes):
    if len(raw_bytes) != 16:
        raise ValueError("GUID must be 16 bytes")
    
    # Extract fields
    data1 = int.from_bytes(raw_bytes[0:4], 'little')
    data2 = int.from_bytes(raw_bytes[4:6], 'little')
    data3 = int.from_bytes(raw_bytes[6:8], 'little')
    data4 = raw_bytes[8:]
    
    # Format as CLSID string
    return f"{{{data1:08X}-{data2:04X}-{data3:04X}-{data4[0]:02X}{data4[1]:02X}-{''.join(f'{b:02X}' for b in data4[2:])}}}"

# Example usage:
raw = bytes.fromhex("d05682fd15fdce11abc402608c9e7553")
print(guid_to_string(raw))