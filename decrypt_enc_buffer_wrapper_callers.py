from blackmatterdecryptor import BlackMatterDecryptor
from blackmatterdecryptor import aplib
import pickle
import string

callers = [4305144, 4305882, 4335988, 4307122, 4307484, 4312960, 4335632, 4312714, 4313456, 4313660, 4327551, 4334552, 4327531, 4327551, 4327691, 4327803, 4327837, 4335241, 4327913, 4328116, 4328220, 4328116, 4335988, 4328248, 4333426, 4334552, 4334552, 4334552, 4335241, 4335632, 4335988, 4337037, 4336487, 4337743]

fpath = r"C:\Users\Kevin\Desktop\Samples\Blackmatter\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368.bin"


def write_pickle(data):
    with open("decrypted_addr.pkl", "wb") as f:
        pickle.dump(data, f)


def extract_utf(data: bytes) -> str:
    try:
        decoded = data.decode('utf-8')
    except UnicodeDecodeError:
        try:
            decoded = data.decode('utf-16')
        except UnicodeDecodeError:
            return None
    if all(c for c in string.printable):  # All printable ASCII
        decoded = "".join(c for c in decoded if 32 <= ord(c) <= 126)
        return decoded
    else: 
        return None

def main():
    bm = BlackMatterDecryptor(fpath)
    bm.decrypt_config()

    decrypted_list = [bm.cust_decrypt_wrapper(caller) for caller in callers]

    extracted_all = []
    addr_decrypted = zip(callers, decrypted_list, strict=True)

    for addr, dec in addr_decrypted:
        if extracted_utf := extract_utf(dec):
            extracted_all.append((addr, extracted_utf))
            continue
        
        decompressed = aplib.aplib_decompress(dec)
        if decompressed_utf := extract_utf(decompressed):
            extracted_all.append((addr, decompressed_utf))
    

    seen = set()
    extracted_unique = []
    for addr, val in extracted_all:
        if val not in seen:
            seen.add(val)
            extracted_unique.append((addr, val))
    return extracted_unique

data = main()
for i in data:
    print({i[1]})
#write_pickle(data)