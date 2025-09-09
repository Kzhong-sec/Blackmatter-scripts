import ida_domain

CUST_DECRYPT_WRAPPER = 0x0406DB0

db = ida_domain.Database()
def get_callers(func_ea):
    return [caller.frm for caller in db.xrefs.get_calls_to(func_ea)]

def get_arg_operand(caller):
    insn = db.instructions.get_at(db.heads.get_prev(caller)) # previous instruction object
    return db.instructions.get_operand(insn, 0)

def get_compile_time_buffers():
    args = [get_arg_operand(i) for i in get_callers(CUST_DECRYPT_WRAPPER)]
    addresses = [arg.get_value() for arg in args if hasattr(arg, 'is_address')]
    return [addr for addr in addresses if addr]

print(get_compile_time_buffers())