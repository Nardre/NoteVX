set sysroot /
set disable-randomization on
set can-use-hw-watchpoints 0
file ./noteVirus

# python function
python
import re

def pie_calc_address(binja_address):
    exe_base = 0x0000555555554000
    binja_base = 0x400000
    offset = binja_address - binja_base
    exe_address = exe_base + offset
    return hex(exe_address)

def pie_break(binja_address):
    exe_address = pie_calc_address(binja_address)
    gdb.execute(f"break *{exe_address}")

def pie_print(binja_address, message):
    exe_address = pie_calc_address(binja_address)

    SIZES = {'hh': 'char', 'h': 'short', 'l': 'long', 'll': 'long', '': 'int'}

    pattern = r'\{(\*?)([^,}]+),\s*%(hh|h|ll|l)?(\w)\}'
    fmt = re.sub(pattern, r'%\4', message)   # gdb ne gère pas %hh/%h/%l -> on ne garde que la lettre

    args = []
    for star, expr, size, kind in re.findall(pattern, message):
        expr = expr.strip()
        if kind == 's':
            args.append(f"*(char**)({expr})" if star else f"(char*)({expr})")
        else:
            ctype = f"unsigned {SIZES[size]}"
            args.append(f"*({ctype}*)({expr})" if star else expr)

    gdb_args = ", ".join(args)
    suffix = f', {gdb_args}' if gdb_args else ''
    gdb.execute(f'dprintf *{exe_address}, "{fmt}\\n"{suffix}')

def pie_watch(binja_address):
    exe_address = pie_calc_address(binja_address)
    gdb.execute(f"watch *{exe_address}")

def pie_print_reg(address):
    pie_print(address, "\\nr90={*0x8049a90, %hhd} r91={*0x8049a91, %hhd} r92={*0x8049a92, %hhd} r93={*0x8049a93, %hhd} r94={*0x8049a94, %hhd}")
    pie_print(address, "d0={*0x08049a84, %hhd} d1={*0x08049a85, %hhd} d2={*0x08049a86, %hhd} d3={*0x08049a87, %hhd} d4={*0x08049a88, %hhd} d5={*0x08049a89, %hhd} d6={*0x08049a8a, %hhd} d7={*0x08049a8b, %hhd} d8={*0x08049a8c, %hhd} d9={*0x08049a8d, %hhd}")
    pie_print(address, "ind={*0x08049a8e, %hd} eax={$eax, %x} esi={$esi, %x}\\n")

end
# gdb script
python pie_break(0x00405000)
run target
