import idautils
import idc

#func_ea = idc.ScreenEA()

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    print(f"Function: {func_name}, Address: 0x{func_ea:X}")

#for head in idautils.FuncItems(func_ea):
    # 명령어 주소와 명령어 텍스트 출력
    #print(f"Address: 0x{head:X}, Instruction: {idc.GetDisasm(head)}")