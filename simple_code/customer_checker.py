import time

ids = [
    {"key": 1, "name": "김대훈", "age": 20},
    {"key": 2, "name": "김중훈", "age": 21},
    {"key": 3, "name": "김소훈", "age": 22},
    {"key": 4, "name": "김민수", "age": 23},
    {"key": 5, "name": "이서준", "age": 24},
    {"key": 6, "name": "박지호", "age": 20},
    {"key": 7, "name": "최유진", "age": 22},
    {"key": 8, "name": "정민서", "age": 21},
    {"key": 9, "name": "한지우", "age": 25},
    {"key": 10, "name": "오지후", "age": 23},
    {"key": 11, "name": "서도윤", "age": 20},
    {"key": 12, "name": "권예준", "age": 22},
    {"key": 13, "name": "황시우", "age": 24},
    {"key": 14, "name": "안하윤", "age": 21},
    {"key": 15, "name": "송서아", "age": 23},
    {"key": 16, "name": "전도현", "age": 20},
    {"key": 17, "name": "홍주원", "age": 22},
    {"key": 18, "name": "조은우", "age": 25},
    {"key": 19, "name": "배지안", "age": 21},
    {"key": 20, "name": "백서준", "age": 23},
    {"key": 21, "name": "유지호", "age": 20},
    {"key": 22, "name": "남서윤", "age": 24},
    {"key": 23, "name": "심예은", "age": 22}
]

def startProtocol():
    text = "고객 조회를 시작합니다..."
    for a in text:
        print(a, end="", flush=True)
        time.sleep(0.05)
    print()

def endProtocol():
    text ="고객 조회를 완료했습니다..."
    for a in text:
        print(a, end="", flush=True)
        time.sleep(0.05)

def lineProtocol():
    print("---------------------------------")

def callId(item):
    return {"id": item["key"], "이름": item["name"], "나이": item["age"]}


startProtocol()
lineProtocol()

for id in ids:
    time.sleep(0.2)
    print(callId(id))

lineProtocol()
endProtocol()