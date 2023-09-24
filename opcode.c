#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "/C:/Users/USER/Documents/GitHub/capstone1/cccapstone-master/cccapstone-master/cppbindings"

int main() {
    // 파일 경로 지정
    char inputFilePath[] = "HelloWorld.exe";
    char outputFilePath[] = "disassembly.txt"; // 출력 파일 경로

    // 입력 파일 열기
    FILE* inputFile = fopen(inputFilePath, "rb");
    if (!inputFile) {
        fprintf(stderr, "Could not open input file.\n");
        return 1;
    }

    // 파일 크기 계산
    fseek(inputFile, 0, SEEK_END);
    long fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    // 파일 내용 읽기
    uint8_t* bytes = (uint8_t*)malloc(fileSize);
    if (!bytes) {
        fprintf(stderr, "Memory allocation failed.\n");
        fclose(inputFile);
        return 1;
    }
    fread(bytes, 1, fileSize, inputFile);
    fclose(inputFile);

    // Capstone 역어셈블러 초기화
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone.\n");
        free(bytes);
        return 1;
    }

    // 출력 파일 열기
    FILE* outputFile = fopen(outputFilePath, "w");
    if (!outputFile) {
        fprintf(stderr, "Could not open output file.\n");
        cs_close(&handle);
        free(bytes);
        return 1;
    }

    // 어셈블리어로 변환하여 출력 및 파일 저장
    size_t offset = 0;
    while (offset < fileSize) {
        cs_insn* insn;
        size_t count = cs_disasm(handle, &bytes[offset], fileSize - offset, offset, 1, &insn);
        if (count > 0) {
            fprintf(outputFile, "0x%lx: %s %s\n", insn->address, insn->mnemonic, insn->op_str);
            offset += insn->size;
            cs_free(insn, 1);
        } else {
            fprintf(stderr, "Failed to disassemble bytes at offset 0x%lx\n", offset);
            break;
        }
    }

    // 파일 닫기
    fclose(outputFile);
    cs_close(&handle);
    free(bytes);

    return 0;
}