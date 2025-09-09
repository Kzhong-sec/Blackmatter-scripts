import ida_domain
db = ida_domain.Database()

def parse_strings(fname):
    address_decString = []
    with open(fname, "r") as f:
        for line in f:
            line = line.strip()
            if "caller:" in line and "decrypted:" in line:
                parts = line.split("caller:")[1].split(", decrypted:")
                caller = parts[0].strip()
                caller = int(caller, base=16)
                decrypted = parts[1].strip()
                address_decString.append((caller, decrypted))
    
    address_decString = set(address_decString)
    return address_decString

def main():
    fname = r'C:\Users\Kevin\Desktop\Samples\Blackmatter\scripts\decrypted_strings.txt'
    address_string = parse_strings(fname)
    for (addr, string) in address_string:
        print(f"commenting {string} at {hex(addr)}")
        db.comments.set(addr, string)
        
main()