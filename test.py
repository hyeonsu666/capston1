import idc

# 현재 선택한 함수의 시작 주소를 가져옴
func_ea = idc.ScreenEA()

# 함수 내의 모든 명령어를 순회하며 출력
for head in idautils.FuncItems(func_ea):
    # 명령어 주소와 명령어 텍스트 출력
    print(f"Address: 0x{head:X}, Instruction: {idc.GetDisasm(head)}")