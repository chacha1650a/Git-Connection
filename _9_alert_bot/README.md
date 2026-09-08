# 로그인 경보 자동화 봇 (실습 과제)

파이썬이 보낸 경보를 n8n 이 판정(허용/거부)하고, 메신저로 알린 뒤 게시판 DB 에 기록한다.

```
[호스트 · 파이썬]              [Docker · n8n]                    [Docker · MySQL]
alert_sender.py                                                   my_new_board_db
     │ ① POST JSON                                                      ▲
     ▼                                                                  │
  Webhook ─▶ Code(판정) ─▶ IF(deny?) ─┬─▶ 슬랙/디스코드/텔레그램 ② 알림   │
                                      └─▶ HTTP Request ── ③ REST ───────┘
                                          host.docker.internal:5000
```

## 파일

| 파일 | 과제 | 내용 |
|---|---|---|
| `alert_sender.py` | 1 | 경보 3건(거부 1 + 허용 2)을 n8n Webhook 으로 POST |
| `n8n_code_node.js` | 2 | Code 노드에 붙여넣을 판정 로직 |
| `n8n_branch_expressions.md` | 3·4 | IF 분기 문구와 게시판 저장 노드 설정 |
| `../_7_board_test/app.py` | 4 | `security_events` REST API (서버측 구현) |

## 실행 순서

1. **켠다** — Docker Desktop / `flask_mysql` / `n8n`(localhost:5678), 그리고 게시판 서버
   ```bash
   cd ../_7_board_test && python app.py
   ```
2. **설정** — 저장소 루트의 `.env.example` 을 `.env` 로 복사해 값을 채운다
   (`DATABASE_URL`, `SECURITY_API_KEY`, `N8N_WEBHOOK_URL`, `STUDENT_NAME`)
3. **실행한다**
   ```bash
   python alert_sender.py
   ```
4. **통과 화면** — `[n8n] POST ... -> 200`, 메신저에 거부/허용 메시지, n8n Executions 전부 초록,
   그리고 DB 에 기록:
   ```sql
   SELECT id, student, src_ip, decision, severity, created_at
   FROM security_events ORDER BY id DESC;
   ```
5. **안 될 때 보는 곳** — 아래 트러블슈팅

## 서버 API (과제 4)

| 메서드 · 경로 | 인증 | 응답 |
|---|---|---|
| `POST /api/security/events` | `X-API-Key` 헤더 | 201 `{id, ...}` / 401 / 400 |
| `GET /api/security/events?student=<이름>` | 없음 | 200, 최신순 |
| `GET /api/security/events/summary?student=<이름>` | 없음 | 200 (심화 S1) |

필수 필드는 `student` · `src_ip` · `decision` 이고, `decision` 은 `allow` 또는 `deny` 만 받는다.

### 검증 결과 (이 저장소에서 실측)
```
키 없이 POST            -> 401
틀린 키로 POST          -> 401
필수값 누락 POST        -> 400  {"missing":["src_ip","decision"]}
정상 POST (deny/allow)  -> 201  id 반환
GET ?student=           -> 200  count=2
GET /summary            -> 200  allow=1 deny=1
n8n 컨테이너 -> 호스트   -> 200  (host.docker.internal:5000 도달 확인)
```

## Code 노드 언어 함정 (체크리스트 B4)

n8n Code 노드는 **JavaScript** 와 **Python (Beta)** 를 고를 수 있는데, 헬퍼 변수 이름이 서로 다르다.

| | JavaScript | Python (Beta) |
|---|---|---|
| 입력 아이템 | `$input.all()` | `_input.all()` |
| 현재 아이템 | `$json` | `_json` |
| 실행 엔진 | Node.js | Pyodide (WebAssembly) |

Python 을 골라 놓고 `$input.all()` 을 쓰면 `$` 가 파이썬 문법에 없어 **즉시 SyntaxError** 가 난다.
게다가 Pyodide 에는 `requests` 같은 패키지가 없고 기동도 느리다.
→ 이 과제는 **JavaScript** 로 작성했다. (`n8n_code_node.js`)

## 트러블슈팅

| 증상 | 원인과 해결 |
|---|---|
| n8n 이 404 | 워크플로우가 Active 인가? Test URL 과 Production URL 은 경로가 다르다 |
| 게시판 저장이 **연결 거부** | ① n8n 은 컨테이너라 `localhost` 는 자기 자신 → `host.docker.internal` 사용<br>② Flask 가 `127.0.0.1` 에만 바인딩되면 컨테이너에서 못 온다 → `app.run(host="0.0.0.0")` |
| 게시판 저장이 **401** | `X-API-Key` 헤더 이름·값이 `.env` 의 `SECURITY_API_KEY` 와 정확히 같은가 |
| 게시판 저장이 **400** | IF 뒤 Set 노드에서 **Include Other Input Fields** 를 껐다 → `src_ip` 등이 사라진 것 |
| 판정이 전부 비어 있음 | Webhook 출력에서 데이터가 `body` 아래 있는지 OUTPUT 패널로 확인 |
| 메신저에 `{{ }}` 그대로 | 입력칸이 표현식 모드(=)인지 확인 |

## 안전 규칙 준수 (체크리스트 E1)

- 비밀값(DB 비밀번호 · API 키 · JWT 키 · Webhook URL)은 **전부 `.env`** 에서만 읽는다.
  저장소에는 값이 빈 `.env.example` 만 올린다. `.env` 는 `.gitignore` 로 제외돼 있다.
- 예시 IP 는 예약 대역만 사용한다 (`1.2.3.x`, `192.168.x.x`, `203.0.113.x`).
- 실제 사람의 계정·이메일·전화번호를 테스트 데이터로 쓰지 않는다.
- n8n 워크플로우를 Export 해서 제출할 때는 JSON 안의 토큰을 `<...>` 로 지운다.
