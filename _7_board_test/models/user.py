from sqlalchemy.types import Integer, TypeDecorator

from extensions import db

# ----------------- 등급(권한) 정의 (과제: 접근 제어 테스트) -----------------
# 카페이야기 등급 체계: 일반(가입 시 기본) < 골드(중간 관리자) < 관리자
ROLE_GENERAL = 0
ROLE_GOLD = 1
ROLE_ADMIN = 2
ROLE_LABELS = {ROLE_GENERAL: '일반', ROLE_GOLD: '골드', ROLE_ADMIN: '관리자'}
_ROLE_NAMES = {'user': ROLE_GENERAL, 'gold': ROLE_GOLD, 'admin': ROLE_ADMIN}


class RoleInt(TypeDecorator):
    """DB 의 role 칼럼이 원본 앱이 만든 VARCHAR('2', 'user' 등)여도 항상 int 로 읽는다."""
    impl = Integer
    cache_ok = True

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, int):
            return value
        if value in _ROLE_NAMES:
            return _ROLE_NAMES[value]
        try:
            return int(value)
        except (TypeError, ValueError):
            return ROLE_GENERAL


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # 0=일반(기본, 최초 가입), 1=골드(중간 관리자), 2=관리자
    role = db.Column(RoleInt, nullable=False, default=ROLE_GENERAL)
    # 권한 부여/회수 감사 추적용 (누가, 언제, 왜 이 등급을 줬는지)
    role_granted_by = db.Column(db.String(80), nullable=True)
    role_granted_at = db.Column(db.DateTime, nullable=True)
    role_reason = db.Column(db.String(200), nullable=True)

    # ----------------- 계정 잠금(account lockout) — 브루트포스 대응 -----------------
    # 로그인 실패가 임계 초과하면 n8n(SOAR)이 /api/admin/lock 을 호출해 잠근다.
    # 잠긴 계정은 비밀번호가 맞아도 로그인 거부(423).
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    locked_at = db.Column(db.DateTime, nullable=True)
    lock_reason = db.Column(db.String(200), nullable=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)  # 표시용(성공 시 0)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_label": ROLE_LABELS.get(self.role, "알수없음"),
            "role_granted_by": self.role_granted_by,
            "role_granted_at": self.role_granted_at.isoformat() + "Z" if self.role_granted_at else None,
            "role_reason": self.role_reason,
            "is_locked": self.is_locked,
            "locked_at": self.locked_at.isoformat() + "Z" if self.locked_at else None,
            "lock_reason": self.lock_reason,
            "failed_logins": self.failed_logins,
        }
