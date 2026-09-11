from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from dotenv import load_dotenv
from functools import wraps
from sqlalchemy import inspect, text
import os
import requests
import hmac
import click

load_dotenv()

app = Flask(__name__)

# 스키마 및 설정
# 비밀값(DB 비밀번호·JWT 시크릿·API 키)은 코드에 쓰지 않고 .env 에서만 읽는다.
# .env 는 .gitignore 로 제외되어 있고, 저장소에는 값이 빈 .env.example 만 올린다.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL 이 설정되지 않았습니다. .env.example 을 복사해 .env 를 만들고 값을 채우세요."
    )

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "dev-only-not-for-submission")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)

# 보안 이벤트 수집 API 가 요구하는 키 (n8n 이 X-API-Key 헤더로 보낸다)
SECURITY_API_KEY = os.getenv("SECURITY_API_KEY")

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ----------------- 등급(권한) 정의 (과제: 접근 제어 테스트) -----------------
# 카페이야기 등급 체계: 일반(가입 시 기본) < 골드(중간 관리자) < 관리자
ROLE_GENERAL = 0
ROLE_GOLD = 1
ROLE_ADMIN = 2
ROLE_LABELS = {ROLE_GENERAL: '일반', ROLE_GOLD: '골드', ROLE_ADMIN: '관리자'}

# ----------------- Database Models -----------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # 0=일반(기본, 최초 가입), 1=골드(중간 관리자), 2=관리자
    role = db.Column(db.Integer, nullable=False, default=ROLE_GENERAL)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_label": ROLE_LABELS.get(self.role, "알수없음"),
        }

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='일반')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))

class SecurityEvent(db.Model):
    """n8n 이 판정한 로그인 경보 1건을 저장한다 (과제 4)."""
    __tablename__ = 'security_events'
    id         = db.Column(db.Integer, primary_key=True)
    student    = db.Column(db.String(80),  nullable=False, index=True)   # 채점 증적용 식별자
    src_ip     = db.Column(db.String(45),  nullable=False)               # IPv6 까지 고려해 45자
    decision   = db.Column(db.String(10),  nullable=False)               # allow / deny
    severity   = db.Column(db.String(10))                                # High / Medium / Low
    reason     = db.Column(db.String(255))
    level      = db.Column(db.Integer)
    rule       = db.Column(db.String(50))
    fail_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "student": self.student,
            "src_ip": self.src_ip,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "level": self.level,
            "rule": self.rule,
            "fail_count": self.fail_count,
            "created_at": self.created_at.isoformat() + "Z",
        }

with app.app_context():
    db.create_all()

    # 이미 만들어져 있던 users 테이블에는 role 컬럼이 없을 수 있으므로
    # (기존 실습 DB에 데이터가 남아있는 경우) 자동으로 컬럼을 추가해준다.
    inspector = inspect(db.engine)
    if 'users' in inspector.get_table_names():
        existing_columns = [col['name'] for col in inspector.get_columns('users')]
        if 'role' not in existing_columns:
            with db.engine.connect() as conn:
                conn.execute(text(
                    f'ALTER TABLE users ADD COLUMN role INTEGER NOT NULL DEFAULT {ROLE_GENERAL}'
                ))
                conn.commit()

# ----------------- 인가(Authorization) 데코레이터 -----------------
def role_required(min_role):
    """로그인 + 최소 등급(min_role) 이상만 통과시킨다. (인증 실패 401, 인가 실패 403)"""
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = User.query.get(int(get_jwt_identity()))
            if not user:
                return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
            if user.role < min_role:
                return jsonify({
                    "msg": "해당 등급의 접근 권한이 없습니다.",
                    "required_role": min_role,
                    "required_role_label": ROLE_LABELS.get(min_role),
                    "your_role": user.role,
                    "your_role_label": ROLE_LABELS.get(user.role),
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ----------------- Auth Endpoints -----------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "아이디와 비밀번호를 입력해주세요."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400

    hashed_password = generate_password_hash(password)
    # 회원가입은 항상 '일반' 등급으로만 생성한다. (등급 상승은 관리자 페이지에서만 가능)
    new_user = User(username=username, password=hashed_password, role=ROLE_GENERAL)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "회원가입이 완료되었습니다."}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token,
        "username": user.username,
        "role": user.role,
        "role_label": ROLE_LABELS.get(user.role),
    }), 200

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def me():
    """현재 로그인한 사용자의 최신 등급을 DB에서 다시 조회해 돌려준다.
    (등급이 바뀐 뒤에도 재로그인 없이 최신 권한을 확인할 수 있도록 하기 위함)"""
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    return jsonify(user.to_dict()), 200

# ----------------- Post Endpoints (RESTful) -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/posts', methods=['GET'])
def get_posts():
    limit = int(request.args.get('limit', 5))
    cursor = request.args.get('cursor', type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '전체')

    query = Post.query

    # 카테고리 필터
    if category and category != '전체':
        query = query.filter(Post.category == category)
    
    # 검색어 필터 (제목 또는 내용)
    if search:
        search_term = f"%{search}%"
        query = query.filter((Post.title.like(search_term)) | (Post.content.like(search_term)))

    # 커서 페이징 처리 (ID 내림차순 기준)
    if cursor:
        query = query.filter(Post.id < cursor)

    query = query.order_by(Post.id.desc())

    # 지정한 limit보다 1개 더 가져와서 다음 페이지 존재 여부 확인
    posts = query.limit(limit + 1).all()

    has_more = False
    next_cursor = None
    if len(posts) > limit:
        has_more = True
        posts = posts[:-1] # 초과분 제거
        next_cursor = posts[-1].id

    posts_list = []
    for post in posts:
        posts_list.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'category': post.category,
            'author': post.author.username if post.author else 'Unknown'
        })

    return jsonify({
        'posts': posts_list,
        'has_more': has_more,
        'next_cursor': next_cursor
    })

@app.route('/api/posts', methods=['POST'])
@jwt_required()
def create_post():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    title = data.get('title')
    content = data.get('content')
    category = data.get('category', '일반')

    if not title or not content:
        return jsonify({"msg": "제목과 내용을 모두 입력해주세요."}), 400

    new_post = Post(
        title=title,
        content=content,
        category=category,
        author_id=current_user_id
    )
    db.session.add(new_post)
    db.session.commit()

    return jsonify({"msg": "게시글이 등록되었습니다."}), 201

@app.route('/api/posts/<int:id>', methods=['PUT'])
@jwt_required()
def update_post(id):
    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(id)

    if str(post.author_id) != str(current_user_id):
        return jsonify({"msg": "수정 권한이 없습니다."}), 403

    data = request.get_json()
    post.title = data.get('title', post.title)
    post.content = data.get('content', post.content)
    post.category = data.get('category', post.category)

    db.session.commit()
    return jsonify({"msg": "게시글이 수정되었습니다."}), 200

@app.route('/api/posts/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_post(id):
    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(id)

    if str(post.author_id) != str(current_user_id):
        return jsonify({"msg": "삭제 권한이 없습니다."}), 403

    db.session.delete(post)
    db.session.commit()
    return jsonify({"msg": "게시글이 삭제되었습니다."}), 200


# ----------------- 등급별 화면 (과제: 접근 제어 테스트) -----------------
# 이 프로젝트는 로그인 상태를 localStorage 의 JWT 로 관리하므로(쿠키 미사용),
# 서버는 페이지 자체는 누구에게나 내려주고, 페이지 안의 JS 가 /api/auth/me 를
# Authorization: Bearer <token> 헤더로 호출해 실제 등급을 확인한 뒤
# 화면에 콘텐츠 또는 "접근 권한 없음" 예외 화면을 그린다.
# ★ 실질적인 접근 제어(진짜 보안)는 아래 /api/admin/... 의 role_required 데코레이터가
#   서버 쪽에서 강제한다. 페이지의 JS 체크는 사용자 경험(화면 분기)일 뿐이다.
@app.route('/gold')
def gold_page():
    return render_template('gold.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# ----------------- 관리자 전용 회원 관리 API -----------------
@app.route('/api/admin/users', methods=['GET'])
@role_required(ROLE_ADMIN)
def admin_list_users():
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200

@app.route('/api/admin/users/<int:id>', methods=['PUT'])
@role_required(ROLE_ADMIN)
def admin_update_user(id):
    target = User.query.get_or_404(id)
    data = request.get_json() or {}

    if 'username' in data and data['username']:
        new_username = data['username']
        dup = User.query.filter(User.username == new_username, User.id != id).first()
        if dup:
            return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400
        target.username = new_username

    if 'role' in data:
        try:
            new_role = int(data['role'])
        except (TypeError, ValueError):
            return jsonify({"msg": "role 값이 올바르지 않습니다."}), 400
        if new_role not in ROLE_LABELS:
            return jsonify({"msg": "role 은 0(일반)/1(골드)/2(관리자) 중 하나여야 합니다."}), 400
        target.role = new_role

    db.session.commit()
    return jsonify({"msg": "회원 정보가 수정되었습니다.", "user": target.to_dict()}), 200

@app.route('/api/admin/users/<int:id>', methods=['DELETE'])
@role_required(ROLE_ADMIN)
def admin_delete_user(id):
    current_user_id = int(get_jwt_identity())
    if id == current_user_id:
        return jsonify({"msg": "본인 계정은 관리자 페이지에서 삭제할 수 없습니다."}), 400

    target = User.query.get_or_404(id)
    # 해당 유저가 작성한 게시글도 함께 정리한다. (author_id 외래키 제약)
    Post.query.filter_by(author_id=target.id).delete()
    db.session.delete(target)
    db.session.commit()
    return jsonify({"msg": "회원이 삭제되었습니다."}), 200


# ----------------- 공공 데이터 연동 설정 (부산테마여행) -----------------
PUBLIC_API_KEY = os.getenv("PUBLIC_API_KEY")
PUBLIC_API_URL = os.getenv("PUBLIC_API_URL")

@app.route('/api/public/posts', methods=['GET'])
def get_public_posts():
    params = {
        'serviceKey': PUBLIC_API_KEY,
        'numOfRows': '100',
        'pageNo': '1',
        'resultType': 'json'
    }
    try:
        response = requests.get(PUBLIC_API_URL, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return jsonify({"msg": "공공 API 호출 실패", "status": response.status_code}), 500
    except Exception as e:
        return jsonify({"msg": "서버 통신 에러 발생", "error": str(e)}), 500

@app.route('/public-posts')
def public_posts_page():
    return render_template('public_posts.html')

@app.route('/public-posts/<int:uc_seq>')
def public_post_detail_page(uc_seq):
    return render_template('public_detail.html', uc_seq=uc_seq)


# ----------------- 보안 이벤트 수집 API (과제 4) -----------------
# n8n 컨테이너 -> 호스트의 이 서버로 POST 된다.
# 컨테이너 안에서 localhost 는 컨테이너 자신이므로, n8n 쪽 URL 은
#   http://host.docker.internal:5000/api/security/events
# 를 써야 한다. (문제지 과제 4 힌트)

REQUIRED_EVENT_FIELDS = ("student", "src_ip", "decision")

def _check_api_key():
    """인증 실패 사유를 담은 응답을 돌려주고, 통과면 None 을 돌려준다."""
    if not SECURITY_API_KEY:
        # 서버가 키를 설정하지 않은 상태 — 인증을 통과시키면 안 된다
        return jsonify({"msg": "서버에 SECURITY_API_KEY 가 설정되지 않았습니다."}), 500
    sent = request.headers.get("X-API-Key")
    if not sent:
        return jsonify({"msg": "X-API-Key 헤더가 없습니다."}), 401
    # 타이밍 공격을 피하려고 단순 == 대신 상수시간 비교를 쓴다
    if not hmac.compare_digest(sent, SECURITY_API_KEY):
        return jsonify({"msg": "X-API-Key 가 올바르지 않습니다."}), 401
    return None

@app.route('/api/security/events', methods=['POST'])
def create_security_event():
    # ① 인증 먼저 (D1·D2 순서: 키가 틀리면 본문 검증 전에 401)
    denied = _check_api_key()
    if denied:
        return denied

    # ② 본문 검증
    data = request.get_json(silent=True) or {}
    missing = [f for f in REQUIRED_EVENT_FIELDS if not data.get(f)]
    if missing:
        return jsonify({"msg": "필수값 누락", "missing": missing}), 400

    if data["decision"] not in ("allow", "deny"):
        return jsonify({"msg": "decision 은 allow 또는 deny 여야 합니다."}), 400

    def _as_int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    # ③ 저장
    event = SecurityEvent(
        student    = str(data["student"])[:80],
        src_ip     = str(data["src_ip"])[:45],
        decision   = data["decision"],
        severity   = (data.get("severity") or None),
        reason     = (str(data["reason"])[:255] if data.get("reason") else None),
        level      = _as_int(data.get("level")),
        rule       = (str(data["rule"])[:50] if data.get("rule") else None),
        fail_count = _as_int(data.get("fail_count")),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify(event.to_dict()), 201

@app.route('/api/security/events', methods=['GET'])
def list_security_events():
    """본인 기록만 최신순 조회 (인증 없음)."""
    student = request.args.get("student")
    if not student:
        return jsonify({"msg": "student 쿼리 파라미터가 필요합니다."}), 400

    rows = (SecurityEvent.query
            .filter_by(student=student)
            .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
            .limit(100)
            .all())
    return jsonify({"student": student, "count": len(rows),
                    "events": [r.to_dict() for r in rows]}), 200

@app.route('/api/security/events/summary', methods=['GET'])
def security_event_summary():
    """(심화 S1) 허용/거부 건수와 거부 상위 IP."""
    student = request.args.get("student")
    if not student:
        return jsonify({"msg": "student 쿼리 파라미터가 필요합니다."}), 400

    counts = dict(
        db.session.query(SecurityEvent.decision, db.func.count(SecurityEvent.id))
        .filter_by(student=student).group_by(SecurityEvent.decision).all()
    )
    top_deny = (db.session.query(SecurityEvent.src_ip, db.func.count(SecurityEvent.id).label("c"))
                .filter_by(student=student, decision="deny")
                .group_by(SecurityEvent.src_ip)
                .order_by(db.desc("c"))
                .limit(5).all())
    return jsonify({
        "student": student,
        "allow": counts.get("allow", 0),
        "deny": counts.get("deny", 0),
        "total": sum(counts.values()),
        "top_deny_ips": [{"src_ip": ip, "count": c} for ip, c in top_deny],
    }), 200


# ----------------- 최초 관리자 부트스트랩용 CLI -----------------
# 회원가입은 항상 '일반' 등급으로만 생성되므로(위 register 참고), 맨 처음
# 관리자 계정을 만들려면 이 CLI 로 등급을 직접 올려야 한다.
# (등급 변경용 API 엔드포인트를 인증 없이 열어두면 그 자체가 취약점이 되므로
#  서버 콘솔에만 존재하는 CLI 명령으로 제공한다.)
# 사용법: flask --app app.py set-role <아이디> <등급 0/1/2>
@app.cli.command('set-role')
@click.argument('username')
@click.argument('role', type=int)
def set_role_command(username, role):
    if role not in ROLE_LABELS:
        click.echo('role 은 0(일반)/1(골드)/2(관리자) 중 하나여야 합니다.')
        return
    user = User.query.filter_by(username=username).first()
    if not user:
        click.echo(f'{username} 사용자를 찾을 수 없습니다.')
        return
    user.role = role
    db.session.commit()
    click.echo(f'{username} 님의 등급을 {ROLE_LABELS[role]}({role}) 로 변경했습니다.')


# ----------------- 앱 실행 -----------------
if __name__ == '__main__':
    # n8n 은 도커 컨테이너 안에 있으므로, 호스트의 127.0.0.1 에만 바인딩하면
    # 컨테이너에서 host.docker.internal 로 들어와도 'Connection refused' 가 난다.
    # 따라서 0.0.0.0 으로 열어 둔다.
    #
    # 주의: 0.0.0.0 + debug=True 는 Werkzeug 디버거가 같은 네트워크에 노출되어
    #       원격 코드 실행으로 이어질 수 있다. 그래서 debug 는 기본을 끄고,
    #       필요할 때만 FLASK_DEBUG=1 로 켜되 신뢰된 망에서만 쓴다.
    host  = os.getenv("FLASK_HOST", "0.0.0.0")
    port  = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"

    if debug and host == "0.0.0.0":
        print("[경고] debug=True 인 채로 0.0.0.0 에 바인딩합니다. 공용 네트워크에서는 쓰지 마세요.")

    app.run(host=host, port=port, debug=debug)