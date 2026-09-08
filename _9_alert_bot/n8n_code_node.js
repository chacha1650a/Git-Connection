// ─────────────────────────────────────────────────────────────
// 과제 2 — n8n Code 노드 (언어: JavaScript / 모드: Run Once for All Items)
// Webhook 이 받은 경보 묶음을 "경보 1건 = 아이템 1개" 로 펼치고 판정한다.
// ─────────────────────────────────────────────────────────────

// 거부 기준 — 이 숫자만 바꾸면 판정이 달라진다 (체크리스트 B3: 10 -> 3 으로 바꿔 비교)
const DENY_LEVEL   = 10;   // 이 값 이상이면 deny / High
const MEDIUM_LEVEL = 7;    // 이 값 이상이면 allow / Medium

const out = [];

for (const item of $input.all()) {
  // Webhook 노드는 POST 본문을 json.body 아래에 넣는다.
  // 테스트 실행 방식에 따라 body 없이 바로 올 수도 있어 양쪽을 모두 받는다.
  const body    = item.json.body ?? item.json;
  const student = body.student ?? 'unknown';
  const alerts  = Array.isArray(body.alerts) ? body.alerts : [];

  for (const a of alerts) {
    const level = Number(a.level ?? 0);

    let severity, decision;
    if (level >= DENY_LEVEL) {
      severity = 'High';   decision = 'deny';
    } else if (level >= MEDIUM_LEVEL) {
      severity = 'Medium'; decision = 'allow';
    } else {
      severity = 'Low';    decision = 'allow';
    }

    out.push({
      json: {
        student,
        src_ip:     a.ip ?? '',
        level,
        rule:       String(a.rule ?? ''),
        fail_count: Number(a.fail_count ?? 0),
        severity,
        decision,
        // 사람이 읽을 수 있는 판정 근거
        reason: `level ${level} (rule ${a.rule ?? '-'}) >= ${DENY_LEVEL} ? -> ${decision} / ${severity}`,
      },
    });
  }
}

// 경보가 하나도 없으면 빈 배열이 되어 뒤 노드가 조용히 멈춘다.
// 그 상황을 눈에 보이게 하려면 아래 주석을 풀어 에러로 만든다.
// if (out.length === 0) throw new Error('경보가 없습니다. Webhook 이 받은 데이터 구조를 OUTPUT 에서 확인하세요.');

return out;
