# 두가지의 수를 입력 받아 
# 1 ~ 4의 선택지중 선택 후 연산하는 프로그램


finalVal = 0

print("두가지 값을 입력 해주세요")

val1 = int(input())
val2 = int(input())

print("---------------------------")
print("어떤 사칙연산을 선택 하시겠습니까?")
print("1. 더하기\n2. 빼기\n3. 곱하기\n4. 나누기")

calType = int(input())

if calType == 1 :
    finalVal += val1 + val2

elif calType == 2:
    finalVal += val1 - val2

elif calType == 3:
    finalVal += val1 * val2

elif calType == 4:
    finalVal += val1 / val2

else : 
    print("입력 값이 올바르지 않습니다.")
    exit()
    

print("계산중입니다...")
print("---------------------------")

print("계산 완료!")
print(finalVal)