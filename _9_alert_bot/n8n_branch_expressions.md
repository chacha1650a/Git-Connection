# 과제 3 — IF 분기와 두 갈래 문구

## 1) IF 노드 설정
- 조건: `{{ $json.decision }}`  **is equal to**  `deny`  (String)
- true 갈래 = 거부, false 갈래 = 허용

## 2) 거부 갈래 문구 (Set 노드, 필드명 `message`)
```
🚫 [거부] {{ $json.src_ip }}
심각도: {{ $json.severity }} | 규칙: {{ $json.rule }} | 실패: {{ $json.fail_count }}회
사유: {{ $json.reason }}
보고자: {{ $json.student }}
```

## 3) 허용 갈래 문구 (Set 노드, 필드명 `message`)
```
✅ [허용] {{ $json.src_ip }} — {{ $json.severity }} ({{ $json.student }})
```

## ⚠️ 반드시 켤 것 — 원본 필드 보존
Set 노드의 **Include Other Input Fields** 를 **켠다** (또는 Mode 를 `Manual Mapping` +
`Include Other Input Fields: All`).

끄면 `message` 만 남고 `src_ip`·`decision`·`student` 가 사라져서,
**과제 4 의 게시판 저장 노드가 400 (필수값 누락)** 을 돌려준다.
→ 문제지 7번 "게시판 저장이 400" 항목이 정확히 이 상황이다.

## 4) 게시판 저장 노드 (HTTP Request)
| 항목 | 값 |
|---|---|
| Method | `POST` |
| URL | `http://host.docker.internal:5000/api/security/events` |
| Authentication | None (헤더로 직접 보냄) |
| Header | `X-API-Key` : `<.env 의 SECURITY_API_KEY 값>` |
| Body Content Type | JSON |
| Body | 아래 |

```json
{
  "student":    "={{ $json.student }}",
  "src_ip":     "={{ $json.src_ip }}",
  "level":      "={{ $json.level }}",
  "rule":       "={{ $json.rule }}",
  "fail_count": "={{ $json.fail_count }}",
  "severity":   "={{ $json.severity }}",
  "decision":   "={{ $json.decision }}",
  "reason":     "={{ $json.reason }}"
}
```

> **URL 주의**: n8n 은 컨테이너 안에 있다. 컨테이너의 `localhost` 는 컨테이너 자신이므로
> `http://localhost:5000` 은 반드시 실패한다. 호스트를 가리키는 `host.docker.internal` 을 쓴다.
> (이 환경에서 도달 확인 완료: `host.docker.internal` → 192.168.65.254)
