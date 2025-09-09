import ida_domain
import struct
import string

db = ida_domain.Database()

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
        
def transform(data: list[int], xor_key) -> list[int]:
    # data is a list of 32-bit integers
    result = []
    for value in data:
        value ^= xor_key  & 0xFFFFFFFF # XOR
        value = ~value & 0xFFFFFFFF  # Bitwise NOT, keep 32-bit
        result.append(value)
    return result

def get_callers(func_ea):
    return [caller.frm for caller in db.xrefs.get_calls_to(func_ea)]

def get_stack_string(caller):
    size_address = db.heads.get_prev(db.heads.get_prev(caller))
    size_insn = db.instructions.get_at(size_address)
    size = db.instructions.get_operand(size_insn, 0)
    size = size.get_value()
    
    dwords = []
    cur_address = size_address
    try:
        i = 0
        while i < size:
            i += 1
            cur_address = db.heads.get_prev(cur_address)
            dword_insn = db.instructions.get_at(cur_address)
            if db.instructions.get_mnemonic(dword_insn) != "mov":
                i -= 1
                continue
            dword = db.instructions.get_operand(dword_insn, 1)
            dword = (dword.get_value() & 0xffffffff)
            dwords.append(dword)
            #print(hex(dword))
        #print(hex(size_address))
    except (AttributeError, TypeError):
        print(f"Unresolved Stack string at {hex(size_address)}")
        return None
    
    return dwords

def resolve_stack_strings(caller, xor_key):
        if dwords := get_stack_string(caller):
            transformed = transform(dwords, xor_key)
            stack_string = b''.join(struct.pack(">I", dword) for dword in transformed)
            stack_string = stack_string[::-1]
            if resolved := extract_utf(stack_string):
                return resolved
            else:
                return str(stack_string)

def main():
    callers = get_callers(0x401250)
    for caller in callers:
        resolved = resolve_stack_strings(caller)
        db.comments.set(caller, resolved)
        print(resolved)
    
main()