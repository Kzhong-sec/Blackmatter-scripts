import binascii
from aplib import BlackMatterDecryptor
import struct
import hashdb_api


def raw_hashlist_to_hashes(hashlist: bytes) -> list[int]:
    hashes = [hashlist[i:i+4] for i in range(0, len(hashlist), 4)]
    hashes = [struct.unpack("<I", hash)[0] for hash in hashes]
    hashes = [hash for hash in hashes if hash]
    return hashes


fpath = r"C:\Users\Kevin\Desktop\Samples\Blackmatter\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368.bin"

bm = BlackMatterDecryptor(fpath)
bm.decrypt_config()
strings = bm.extract_all()

print(bm.cust_decrypt_wrapper(0x0041B25A))