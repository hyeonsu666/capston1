def extract_instructions():
    # 분석할 바이너리 파일의 주소를 설정
    binary_path = "C:\Users\코코아 프렌즈\Documents\GitHub\capstone1\HelloWorld.exe"

    with open(binary_path, "rb") as file:
        binary_data = file.read()

    # IDA Pro와 독립적인 Python 스크립트로 어셈블리 명령어를 추출하는 로직을 작성
    # 이 부분은 IDA Pro 환경과는 관련이 없으며, 원하는 바이너리 파일에 대한 처리입니다.
    # 바이너리 데이터를 분석하고 어셈블리 명령어를 추출하는 로직을 여기에 작성하세요.

if __name__ == "__main__":
    extract_instructions()