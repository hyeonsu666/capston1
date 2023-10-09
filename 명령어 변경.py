# 난독화할 대상 명령 확인
def is_instruction_to_obfuscate(mnemonic):
    return mnemonic in ["add", "sub", "xor", "mov"]

# 명령 난독화
def obfuscate_instruction(instruction):
    if len(instruction) >= 2:
        operand1 = instruction[0]
        operand2 = instruction[1]
        new_operand1 = operand1 + operand2  # 예: 두 피연산자의 합
        return f"mov {operand1}, {new_operand1}"  # 난독화된 명령 반환
    return None

# 난독화할 함수 내용
def obfuscate_function(function):
    obfuscated_code = []
    for instruction in function:
        mnemonic = instruction[0]
        if is_instruction_to_obfuscate(mnemonic):
            obfuscated = obfuscate_instruction(instruction)
            if obfuscated:
                obfuscated_code.append(obfuscated)
        else:
            obfuscated_code.append(' '.join(instruction))
    return obfuscated_code

# 스크립트 실행
if __name__ == "__main__":
    # 테스트용 함수 내용
    sample_function = [
        ["mov", "eax", "10"],
        ["add", "eax", "20"],
        ["mov", "ebx", "30"],
        ["sub", "ebx", "5"],
    ]

    obfuscated_code = obfuscate_function(sample_function)

    for line in obfuscated_code:
        print(line)
