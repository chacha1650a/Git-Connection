import os
import time

path = "C:\gov"
file_check_start = "파일 목록을 불러오는 중입니다..."

try: 
    file_list= os.listdir(path)

    for text in file_check_start:
        print(text, end="", flush=True)
        time.sleep(0.1)
    print()

    time.sleep(1)

    for file in file_list:
        for char in file:
            print(char, end="", flush=True)
            time.sleep(0.001)
        print()
        time.sleep(0.3)

except PermissionError:
    print("접근 권한이 없습니다!")