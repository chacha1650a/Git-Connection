"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent · BlockedIP
  controllers/    page · auth · post · gold · admin · security · public (블루프린트)
  templates/      화면 (partials/_nav.html = 공통 반응형 헤더)

실행:  python app.py   →  http://localhost:5000
"""
import os

import click
from flask import Flask, jsonify, request
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from extensions import db, jwt
from models import BlockedIP, User
from models.user import ROLE_GENERAL, ROLE_LABELS


def _client_ip():
    """요청의 실제 클라이언트 IP. 프록시(n8n·nginx) 뒤면 X-Forwarded-For 첫 홉을 신뢰.
    (랩 한정 규칙 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def _ensure_schema():
    """이미 만들어져 있던 users/security_events 테이블에는 새로 추가한 컬럼이
    없을 수 있으므로(기존 실습 DB에 데이터가 남아있는 경우) 자동으로 추가해준다."""
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    column_adds = {
        'users': {
            'role': f'ALTER TABLE users ADD COLUMN role INTEGER NOT NULL DEFAULT {ROLE_GENERAL}',
            'role_granted_by': 'ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80) NULL',
            'role_granted_at': 'ALTER TABLE users ADD COLUMN role_granted_at DATETIME NULL',
            'role_reason': 'ALTER TABLE users ADD COLUMN role_reason VARCHAR(200) NULL',
        },
        'security_events': {
            'source': 'ALTER TABLE security_events ADD COLUMN source VARCHAR(50) NULL',
            'level': 'ALTER TABLE security_events ADD COLUMN level INTEGER NULL',
            'rule': 'ALTER TABLE security_events ADD COLUMN rule VARCHAR(50) NULL',
        },
    }
    with db.engine.begin() as conn:
        for table, adds in column_adds.items():
            if table not in tables:
                continue
            existing = {c['name'] for c in inspector.get_columns(table)}
            for name, ddl in adds.items():
                if name not in existing:
                    conn.execute(text(ddl))


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 확장 초기화
    db.init_app(app)
    jwt.init_app(app)

    # 컨트롤러(블루프린트) 등록
    for bp in all_blueprints:
        app.register_blueprint(bp)

    # 테이블 생성 (models 를 import 한 뒤여야 한다 — controllers 가 이미 import 함)
    with app.app_context():
        db.create_all()
        _ensure_schema()

    @app.before_request
    def _block_ip_guard():
        """실차단(active response): 차단된 IP 의 요청은 앱에 닿기 전에 403 으로 되돌린다.

        - 관리자 API(/api/admin/*) 는 예외 — 그래야 운영자·n8n 이 차단/해제를 계속 할 수 있다
          (자기 자신을 잠가 복구 불능이 되는 것을 막는 안전장치).
        - 매 요청 blocked_ips 표를 조회한다. 랩 규모에선 충분하고, 실서비스는
          캐시(예: Redis)나 방화벽(nftables) 계층으로 올려야 한다."""
        if request.path.startswith('/api/admin'):
            return None
        ip = _client_ip()
        if ip and db.session.get(BlockedIP, ip):
            return jsonify({"msg": "차단된 IP 입니다(관리자에게 문의).", "ip": ip, "blocked": True}), 403
        return None

    # ----------------- 최초 관리자 부트스트랩용 CLI -----------------
    # 회원가입은 항상 '일반' 등급으로만 생성되므로, 맨 처음 관리자 계정을 만들려면
    # 이 CLI 로 등급을 직접 올려야 한다. (등급 변경용 API 를 인증 없이 열어두면
    # 그 자체가 취약점이 되므로 서버 콘솔에만 존재하는 CLI 명령으로 제공한다.)
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

    return app


app = create_app()


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
