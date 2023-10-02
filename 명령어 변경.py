import idc
import idautils
import idaapi

def obfuscate_functions():
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if func is not None:
            obfuscate_function(func)

# 함수 내용 난독화
def obfuscate_function(func):
    for block in idaapi.FlowChart(func):
        for head in idautils.Heads(block.startEA, block.endEA):
            if is_instruction_to_obfuscate(head):
                obfuscate_instruction(head)
                print(f"Obfuscated instruction at 0x{head:X}")

# 난독화할 대상 명령 확인
def is_instruction_to_obfuscate(ea):
    mnem = idc.GetMnem(ea)
    return mnem in ["add", "sub", "xor", "mov"]

# 명령 난독화
def obfuscate_instruction(ea):
    operand_count = idc.GetOpType(ea, 0)
    if operand_count >= 2:
        operand1 = idc.GetOperandValue(ea, 0)
        operand2 = idc.GetOperandValue(ea, 1)
        new_operand1 = operand1 + operand2  # 예: 두 피연산자의 합
        idc.OpSetOperandType(ea, 0, idc.o_imm)
        idc.OpSetOperandValue(ea, 0, new_operand1)

# 스크립트 실행
if __name__ == "__main__":
    obfuscate_functions()

#명령어 변경