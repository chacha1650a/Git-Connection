"""과잉권한 admin 탐지 → Graylog(GELF) 신고 봇 (문서 5장).

게시판 회원 중 허용목록(ADMIN_ALLOWLIST) 밖의 admin 을 찾아 Graylog 로 신고한다.
표준 라이브러리만 사용 — 설치 없이 바로 실행 가능. 비밀값은 같은 폴더 .env
또는 환경변수에서 읽는다.

사용법:
    python privilege_revoke_bot.py --dry-run   # 신고 없이 위반만 출력
    python privilege_revoke_bot.py             # 탐지 + Graylog 신고
    python privilege_revoke_bot.py --revoke    # 신고 + n8n 없이 봇이 직접 회수
"""
import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _load_env_file(path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_env_file(Path(__file__).with_name(".env"))

BOARD_URL = os.environ.get("BOARD_URL", "http://localhost:5000").rstrip("/")
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY") or os.environ.get("SECURITY_API_KEY", "")
ADMIN_ALLOWLIST = {u.strip() for u in os.environ.get("ADMIN_ALLOWLIST", "").split(",") if u.strip()}
GRAYLOG_HOST = os.environ.get("GRAYLOG_HOST", "localhost")
GRAYLOG_GELF_PORT = int(os.environ.get("GRAYLOG_GELF_PORT", "12201"))


def fetch_admin_users():
    req = urllib.request.Request(
        f"{BOARD_URL}/api/admin/users?role=admin",
        headers={"X-API-Key": ADMIN_API_KEY},
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))["users"]


def find_violations(users):
    return [u for u in users if u["username"] not in ADMIN_ALLOWLIST]


def send_gelf(user, src_ip="127.0.0.1"):
    """GELF UDP 메시지 1건을 Graylog 로 보낸다.
    ★ 커스텀 필드(_rule 등)는 Graylog 색인 시 앞의 _ 가 벗겨져 rule 로 저장된다
    (문서 6-2 실측 함정 — 이벤트 정의 필터는 rule:... 로 써야 한다)."""
    message = {
        "version": "1.1",
        "host": socket.gethostname(),
        "short_message": f"privilege violation: '{user['username']}' has unauthorized admin",
        "level": 5,
        "_rule": "priv-unauthorized-admin",
        "_user": user["username"],
        "_granted_by": user.get("role_granted_by") or "apikey",
        "_src_ip": src_ip,
    }
    payload = json.dumps(message).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (GRAYLOG_HOST, GRAYLOG_GELF_PORT))
    finally:
        sock.close()


def revoke_user(username, reason="과잉권한 자동회수 (봇 --revoke, n8n 미경유)"):
    req = urllib.request.Request(
        f"{BOARD_URL}/api/admin/revoke",
        method="POST",
        headers={"X-API-Key": ADMIN_API_KEY, "Content-Type": "application/json"},
        data=json.dumps({"username": username, "reason": reason, "src_ip": "127.0.0.1"}).encode("utf-8"),
    )
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="과잉권한 admin 탐지 봇")
    parser.add_argument("--dry-run", action="store_true", help="신고 없이 위반만 출력")
    parser.add_argument("--revoke", action="store_true", help="Graylog/n8n 없이 봇이 직접 회수")
    args = parser.parse_args()

    if not ADMIN_API_KEY:
        print("[!] ADMIN_API_KEY(또는 SECURITY_API_KEY) 가 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    try:
        users = fetch_admin_users()
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"[!] 게시판 API 호출 실패: {e}", file=sys.stderr)
        sys.exit(1)

    violations = find_violations(users)
    if not violations:
        print("[OK] 과잉권한 admin 없음.")
        return

    print(f"[!] 과잉권한 admin {len(violations)}건 탐지: " + ", ".join(v["username"] for v in violations))
    for v in violations:
        granted_by = v.get("role_granted_by") or "apikey"
        if args.dry_run:
            print(f"    - {v['username']} (부여자 {granted_by}) [dry-run]")
            continue

        send_gelf(v)
        print(f"    - {v['username']} (부여자 {granted_by}) -> Graylog 신고 완료")

        if args.revoke:
            try:
                result = revoke_user(v["username"])
                print(f"      회수 결과: {result}")
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                print(f"      [!] 회수 API 호출 실패: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
