import lief
import random
import subprocess

def obfuscate_instructions(binary_path):
    # 바이너리 파일 열기
    binary = lief.parse(binary_path)
    
    # 난독화할 대상 명령어 목록
    instructions_to_obfuscate = ["add", "sub", "xor", "mov"]
    
    for function in binary.functions:
        for basic_block in function.basic_blocks:
            for instruction in basic_block.instructions:
                # 명령어가 난독화 대상에 포함되어 있는지 확인
                if instruction.mnemonic in instructions_to_obfuscate:
                    obfuscate_instruction(instruction)

    # 난독화된 바이너리 파일 저장
    obfuscated_binary_path = binary_path.replace(".exe", "_obfuscated.exe")
    binary.write(obfuscated_binary_path)

def obfuscate_instruction(instruction):
    # 예제: 난독화된 명령어로 대체
    # 여기에서는 두 피연산자의 값을 더하는 난독화를 예로 들었습니다.
    operand1 = instruction.operands[0]
    operand2 = instruction.operands[1]
    new_value = operand1.value + operand2.value
    operand1.value = new_value
    operand2.value = 0

#if __name__ == "__main__":
#    binary_path = "C:\Users\코코아 프렌즈\Documents\GitHub\capstone1\HelloWorld(1).exe"  # 분석할 바이너리 파일 경로 설정
#    obfuscate_instructions(binary_path)

    # 난독화된 바이너리 파일을 실행
#    obfuscated_binary_path = binary_path.replace(".exe", "_obfuscated.exe")
#    subprocess.run([obfuscated_binary_path])

