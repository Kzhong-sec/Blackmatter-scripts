idx = 0x07F1CC1 # final 3 random bytes of matrix in little endian

edx = (idx * 0x8088405) & 0xffffffff
edx = (edx + 1) & 0xffffffff
edx = (edx * 120)# & 0xff00000000
edx = edx >> 32
print(hex(edx))