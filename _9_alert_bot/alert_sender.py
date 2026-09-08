"""
alert_sender.py — 로그인 경보를 n8n Webhook 으로 보내는 전송기 (과제 1)

실행:  python alert_sender.py
사전:  프로젝트 루트의 .env 에 N8N_WEBHOOK_URL 을 설정해 둘 것
       (.env.example 참고. Webhook URL 은 비밀값이므로 코드에 직접 쓰지 않는다 — 안전규칙 8)
"""
import json
import os
import sys

import requests
from dotenv import load_dotenv, find_dotenv

# ─────────── 설정 상수 (바꿀 값은 전부 여기에 모아 둔다) ───────────
load_dotenv(find_dotenv(usecwd=True))

STUDENT      = os.getenv("STUDENT_NAME", "홍길동")   # 채점 증적용 본인 식별자
N8N_WEBHOOK  = os.getenv("N8N_WEBHOOK_URL")          # n8n 워크플로우의 Production URL
TIMEOUT_SEC  = 10

# 보낼 경보 목록 — 거부될 것(level >= 10)과 허용될 것(level < 10)이 모두 들어 있다.
# IP 는 문서 예약 대역만 사용한다 (안전규칙 8: 실제 IP·개인정보 금지)
ALERTS = [
    {"ip": "1.2.3.114",    "level": 10, "rule": "5712", "fail_count": 8},  # -> deny  / High
    {"ip": "203.0.113.77", "level": 7,  "rule": "5716", "fail_count": 5},  # -> allow / Medium
    {"ip": "192.168.0.10", "level": 3,  "rule": "5710", "fail_count": 1},  # -> allow / Low
]
# ────────────────────────────────────────────────────────────────


def build_payload():
    return {"student": STUDENT, "alerts": ALERTS}


def main():
    if not N8N_WEBHOOK:
        print("[설정오류] N8N_WEBHOOK_URL 이 비어 있습니다.")
        print("          .env.example 을 복사해 .env 를 만들고 값을 채우세요.")
        return 2

    payload = build_payload()
    print(f"[보낼 데이터] student={payload['student']}, 경보 {len(payload['alerts'])}건")
    print(json.dumps(payload, ensure_ascii=False, indent=2))

    try:
        res = requests.post(N8N_WEBHOOK, json=payload, timeout=TIMEOUT_SEC)
        print(f"[n8n] POST {N8N_WEBHOOK} -> {res.status_code}")
        if res.text:
            print(f"[응답] {res.text[:300]}")
        return 0 if res.ok else 1

    # ↓ n8n 이 꺼져 있어도 프로그램이 죽지 않고 사유를 알려 준다 (체크리스트 A3)
    except requests.exceptions.ConnectionError:
        print(f"[전송실패] n8n 에 연결할 수 없습니다: {N8N_WEBHOOK}")
        print("           n8n 컨테이너가 떠 있는지(docker ps), 주소가 맞는지 확인하세요.")
    except requests.exceptions.Timeout:
        print(f"[전송실패] 응답이 {TIMEOUT_SEC}초 안에 오지 않았습니다.")
    except requests.exceptions.RequestException as e:
        print(f"[전송실패] 요청 중 오류: {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
