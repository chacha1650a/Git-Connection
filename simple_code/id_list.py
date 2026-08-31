# dictionary 안에 담겨있는 데이터를 key로 호출,
# value로 받아와서 0.2초마다 출력,
# 하나의 dictionary가 끝나면 다음으로 넘어가는 
# id 조회 프로그램

import time

lists = [{"num": 1, "name": "김대훈", "age": 20},
         {"num": 2, "name": "김중훈", "age": 21},
         {"num": 3, "name": "김소훈", "age": 22}]

for ids in lists:
    for val in ids.values():
        # 각 값(숫자, 문자열 등)을 문자열로 바꾼 뒤 한 글자씩 쪼갭니다
        for char in str(val):
            print(char, end="", flush=True)
            time.sleep(0.2)
        print(" ", end="", flush=True)  # 값과 값 사이 공백
    print()  # 한 줄이 끝나면 줄바꿈

print()