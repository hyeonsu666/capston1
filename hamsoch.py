import idc
import idaapi
import idautils
import random

# 난독화할 함수 리스트 (여기서는 모든 함수를 대상으로 함)
def obfuscate_functions():
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if func is not None:
            obfuscate_function(func)

# 함수 내용 난독화
def obfuscate_function(func):
    # 함수 내용을 가져옴
    start_ea = func.startEA
    end_ea = func.endEA
    size = end_ea - start_ea

    # 무작위 바이트로 함수 내용을 덮어씀
    for ea in range(start_ea, end_ea):
        idc.PatchByte(ea, random.randint(0, 255))

    print(f"Function at 0x{start_ea:X} obfuscated")

# 스크립트 실행
if __name__ == "__main__":
    obfuscate_functions()

#각 바이트를 무작위로 변경하여 함수 내용을 완전히 바꿔버림