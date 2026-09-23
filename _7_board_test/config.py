"""설정 한 곳에 모으기.

비밀값(DB 비밀번호·JWT 키·API 키)은 코드에 쓰지 않고 같은 폴더의 .env 에서 읽는다.
.env 는 절대 깃에 올리지 않는다(.gitignore).
"""
import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()  # .env → 환경변수 (import 시점 1회)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL 이 설정되지 않았습니다. .env.example 을 복사해 .env 를 만들고 값을 채우세요."
    )

# 보안 이벤트 수집 API 가 요구하는 키 (n8n 이 X-API-Key 헤더로 보낸다)
SECURITY_API_KEY = os.getenv("SECURITY_API_KEY")

# 관리자 API(권한 부여/회수)를 기계(파이썬 봇·n8n)가 두드릴 때 쓰는 키.
# 비어 있으면 SECURITY_API_KEY 로 대체한다(문서 4-3).
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY") or SECURITY_API_KEY

# 이 목록 밖의 admin 은 과잉권한으로 간주해 회수 대상이 된다(콤마 구분).
ADMIN_ALLOWLIST = {u.strip() for u in os.getenv("ADMIN_ALLOWLIST", "").split(",") if u.strip()}

# 공공 데이터 연동 설정 (부산테마여행)
PUBLIC_API_KEY = os.getenv("PUBLIC_API_KEY")
PUBLIC_API_URL = os.getenv("PUBLIC_API_URL")


class Config:
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # debug=False 여도 templates/*.html 수정은 재시작 없이 바로 반영되게 한다.
    TEMPLATES_AUTO_RELOAD = True
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-only-not-for-submission")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

    SECURITY_API_KEY = SECURITY_API_KEY
    ADMIN_API_KEY = ADMIN_API_KEY
    ADMIN_ALLOWLIST = ADMIN_ALLOWLIST

    PUBLIC_API_KEY = PUBLIC_API_KEY
    PUBLIC_API_URL = PUBLIC_API_URL

    # ── Graylog GELF (앱이 로그인 실패 등 보안 로그를 SIEM 으로 전송) ──
    GELF_HOST = os.getenv('GELF_HOST', 'localhost')
    GELF_PORT = int(os.getenv('GELF_PORT', '12201'))
