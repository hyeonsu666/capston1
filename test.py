import idautils
import idc


for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    print(f"Function: {func_name}, Address: 0x{func_ea:X}")

