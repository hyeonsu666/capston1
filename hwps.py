import idautils
import idaapi

def extract_instructions():
    # 모든 함수를 순회하며 명령어를 추출
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if func is not None:
            print(f"Function: {idaapi.get_func_name(func_ea)}")
            
            # 함수 내의 모든 기본 블록을 순회하며 명령어를 추출
            for block in idaapi.FlowChart(func):
                for insn in idautils.FuncItems(block.startEA):
                    # 명령어 주소와 명령어 텍스트 출력
                    print(f"Address: 0x{insn:X}, Instruction: {idc.GetDisasm(insn)}")

if __name__ == "__main__":
    extract_instructions()