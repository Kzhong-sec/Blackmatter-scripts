EA_HASH_ARG_START = 0x004063ED
EA_HASH_ARG_END = 0x00406524
STEP_BETWEEN_ARGS = 17
XOR_KEY = 0x4803BFC7
ALGORITHM = 'ror13_add'
API_HASH_LIST_END_MARKER = 0xCCCCCCCC

from ida_domain import *
import idaapi
import requests
import time

db = Database()

def get_func_operands(arg_start, arg_end, step_between_args):
    insn_ea = list(range(arg_start, arg_end, step_between_args))
    operands = [idaapi.get_dword(operand + 1) for operand in insn_ea] #+1 negates the push instruction, just retrieves the operand
    return operands


def bmatter_retrieve_hashes(ea_hash_arg_start, ea_hash_arg_end)->tuple[list[int], list[list]]:
    # retrieving addresses of code that push a hash struct to the function
    operands = get_func_operands(ea_hash_arg_start, ea_hash_arg_end, STEP_BETWEEN_ARGS)
    dll_hashes = [idaapi.get_dword(dll_hash) for dll_hash in operands]
    dword = 4
    api_hashes = []
    for api_hashes_per_dll in operands:
        hashes_ea = api_hashes_per_dll + dword
        cur_dll_api_hashes = []
        while (api_hash := idaapi.get_dword(hashes_ea)) != API_HASH_LIST_END_MARKER:
            cur_dll_api_hashes.append(api_hash)
            hashes_ea += dword
        api_hashes.append(cur_dll_api_hashes)

    return dll_hashes, api_hashes   # first member is dll hash, second member is API hash

def resolve_api_hash(hash: int, algorithm: str = ALGORITHM, xor: int = None):
    if xor:
        xor = str(xor)
        hashdb_api = f'https://hashdb.openanalysis.net/hash/{algorithm}/{hash}/{xor}'
    else:
        hashdb_api = f'https://hashdb.openanalysis.net/hash/{algorithm}/{hash}'
    
        
    while True:
        response = requests.get(hashdb_api)
        if response.status_code == 429:
            print("Getting rate limited")
            time.sleep(60)
            continue
        else:
            data = response.json()
        
        hashes = data.get('hashes', [])
        if hashes:
            first_hash = hashes[0]
            string_data = first_hash.get('string')
            if string_data:
                string = string_data.get('string')
        return string

        
def retrieve_resolved_out_base(ea_out_arg_start, ea_out_arg_end):
    out_addrs = get_func_operands(ea_out_arg_start, ea_out_arg_end, STEP_BETWEEN_ARGS)
    out_addrs = [out+4 for out in out_addrs]
    return out_addrs


def main():
    _, api_hashes = bmatter_retrieve_hashes(EA_HASH_ARG_START, EA_HASH_ARG_END)

    resolved_out_base = retrieve_resolved_out_base(EA_HASH_ARG_START+5, EA_HASH_ARG_END+5) # out arg is pushed right after hashes, in a 5 byte instruction
    
    for apis_for_dll, hash_list in enumerate(api_hashes):
        for offset, hash in enumerate(hash_list):
            api_name = resolve_api_hash(hash, ALGORITHM, XOR_KEY)
            if api_name:
                db.names.force_name(resolved_out_base[apis_for_dll]+(offset*4), api_name)
                print(f'{api_name} at {hex(resolved_out_base[apis_for_dll]+offset*4)}')
            else:
                print(f"unable to resolve hash: {hex(hash)}, at {hex(resolved_out_base[apis_for_dll]+(offset*4))}")

if __name__ == "__main__":

    main()