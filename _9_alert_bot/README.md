# 로그인 경보 자동화 봇

## ① 무엇을 만들었나

파이썬이 로그인 실패 경보(레벨·IP·규칙)를 n8n Webhook으로 보내면, n8n이 레벨을 보고 **허용(allow)/거부(deny)를 스스로 판정**해서 슬랙·디스코드·텔레그램 3곳에 서로 다른 문구로 알리고, 동시에 Flask + MySQL로 만든 게시판 서버의 REST API를 호출해 판정 결과를 DB에 기록하는 자동화 파이프라인입니다.

```
[파이썬] alert_sender.py
     │ POST (student, alerts[])
     ▼
[n8n] Webhook → 판정(JavaScript) → IF(거부인가?)
                                     ├─ deny → 🚫 문구 ─┬→ 슬랙
                                     │                  ├→ 디스코드
                                     │                  ├→ 텔레그램
                                     │                  └→ 게시판 저장(REST)
                                     └─ allow → ✅ 문구 ─┴→ (위와 동일 4곳)
                                                              │
                                                              ▼
                                              [Flask + MySQL] security_events 테이블
```

## ② 작업 내역

1. **게시판 서버(Flask + MySQL)**에 `security_events` 테이블과 REST API 3종 추가
   - `POST /api/security/events` — `X-API-Key` 인증, 저장 후 201
   - `GET /api/security/events?student=` — 본인 기록 최신순 조회
   - `GET /api/security/events/summary?student=` — 허용/거부 집계 (심화)
2. **파이썬 전송기** `alert_sender.py` 작성 — 경보 2건 이상(거부 대상 포함)을 n8n Webhook으로 POST, 실패해도 죽지 않고 사유 출력
3. **n8n 워크플로우** 구성
   - `Webhook` → `판정(JavaScript)`: 경보 배열을 아이템으로 펼치며 레벨로 severity/decision 판정
   - `IF(거부인가?)`: `decision == deny` 로 두 갈래 분기
   - 각 갈래에서 문구를 다르게 만든 뒤 슬랙·디스코드·텔레그램·게시판 저장 4곳으로 팬아웃
4. **보안 정리**: DB 비밀번호·JWT 키·API 키·Webhook URL을 전부 `.env`로 옮기고, 값이 빈 `.env.example`만 저장소에 포함

## 사용한 것

- **파이썬** 3.13 (`requests`, `python-dotenv`)
- **n8n** 2.37.7 (Docker) — Webhook, Code(JavaScript), IF, Edit Fields(Set), HTTP Request 노드
- **MySQL** 8.0 (Docker) — `security_events` 테이블
- **Flask + SQLAlchemy** — 게시판 서버 겸 보안 이벤트 REST API
- **메신저**: 슬랙, 디스코드, 텔레그램 — **3종 전부 실제 연결** (대체 없음)

## ③ 기능 구현 화면

*(아래 캡처는 images/ 폴더에 넣고 파일명 맞춰주세요 — ⚠️ 캡처 전에 API 키·Webhook URL이 화면에 보이지 않는지 반드시 확인!)*

**n8n 워크플로우 전체 화면**
![워크플로우 전체](images/01_workflow_full.png)

**Code 노드 판정 결과 (아이템 2개, decision/severity 확인)**
![판정 결과](images/02_code_output.png)

**IF 분기 — 두 갈래 모두 초록 실행**
![IF 분기](images/03_if_branch.png)

**메신저 도착 화면**
![슬랙](images/04_slack.png)
![디스코드](images/05_discord.png)
![텔레그램](images/06_telegram.png)

**파이썬 전송기 실행 화면**
![전송기 실행](images/07_sender.png)

**MySQL 저장 결과**
![DB 결과](images/08_mysql.png)

**게시판 REST API 응답 (401/400/201/GET)**
![API 검증](images/09_api_test.png)

## ④ 실행 방법

1. **켠다**
   - Docker: MySQL 컨테이너(`flask_mysql`), n8n 컨테이너
   - 게시판 서버: `cd _7_board_test && python app.py`
   - n8n 워크플로우 `Active` 토글 켜기
2. **설정**: 저장소 루트의 `.env.example`을 `.env`로 복사해 값 채우기 (`DATABASE_URL`, `SECURITY_API_KEY`, `N8N_WEBHOOK_URL`, `STUDENT_NAME` 등)
3. **실행한다**: `cd _9_alert_bot && python alert_sender.py`
4. **성공 화면**: 터미널에 `[n8n] POST ... -> 200`, 메신저 3곳에 거부/허용 메시지, MySQL `security_events`에 행 추가
5. **안 될 때 보는 곳**: n8n `Executions` 탭에서 어느 노드가 빨간 X인지 확인 → 아래 트러블슈팅 표 참고

## ⑤ 막혔던 점과 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| Code 노드를 Python으로 바꾸니 즉시 에러 | n8n 컨테이너에 Python 3 런타임 자체가 없어서 Internal 모드에서 Python 실행이 원천 불가능 (`Python runner unavailable`) | JavaScript로 전환. n8n Code 노드는 Node.js 기반이라 별도 설치 없이 바로 동작 |
| 게시판 저장 노드가 "연결 거부" | 게시판 Flask 서버(5000)가 꺼져 있었음 (n8n은 컨테이너 안이라 호스트의 `localhost`에 못 닿음 → `host.docker.internal` 사용 + 서버 실행 필요) | `python app.py`로 서버 실행, URL을 `host.docker.internal:5000`으로 지정 |
| 게시판 저장이 계속 400 | HTTP Request Body를 "Using JSON" 모드로 쓰면서 각 값 앞에 `=`를 붙여, `{{ }}` 표현식이 평가 안 되고 문자 그대로(`=deny`) 전송됨 | 각 필드 값 앞의 `=` 제거, `{{ $json.xxx }}`만 남김 |
| IF 조건이 의도대로 안 갈림 | 값을 복사하면서 탭 문자가 섞여 들어가 문자열 비교가 실패함 | 입력칸을 비우고 깨끗하게 다시 타이핑 |

## 안전 확인

- DB 비밀번호·JWT 키·API 키·Webhook URL은 전부 `.env`에서만 관리, `.gitignore`로 커밋 제외
- 저장소에는 값이 없는 `.env.example`만 포함
- 위 캡처들은 게시 전 API 키·토큰·Webhook 전체 URL이 찍히지 않았는지 확인 완료
