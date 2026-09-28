"""등급별 접근제어(RBAC) 테스트 — user < gold < admin.

실습용 MySQL 을 건드리지 않도록 임시 SQLite 파일에 별도 앱을 띄워 검사한다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db
from models import Post, User

PW = 'pw12345'


@pytest.fixture
def app(tmp_path):
  """테스트 전용 앱 — 임시 SQLite. 실습 DB 와 완전히 분리된다."""
  class TestConfig:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'test-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECURITY_API_KEY = 'test-security-key'
    ADMIN_API_KEY = 'test-admin-key'
    ADMIN_ALLOWLIST = []
    AUTO_POST_ON_DENY = False
    PUBLIC_API_KEY = None
    PUBLIC_API_URL = 'http://example.invalid/'

  application = create_app(TestConfig)
  yield application
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


@pytest.fixture
def client(app):
  return app.test_client()


# ── 도우미 ──────────────────────────────────────────────
def register(client, username):
  return client.post('/api/auth/register',
                     json={'username': username, 'password': PW})


def login(client, username):
  res = client.post('/api/auth/login',
                    json={'username': username, 'password': PW})
  return res.get_json()['access_token']


def auth(token):
  return {'Authorization': f'Bearer {token}'}


KEY = {'X-API-Key': 'test-admin-key'}


def set_role(client, username, role):
  """관리자 API 키로 역할을 바꾼다(테스트 준비용)."""
  return client.post('/api/admin/grant', headers=KEY,
                     json={'username': username, 'role': role,
                           'reason': 'test'})


# ── 로그인 응답 · 내 정보 ────────────────────────────────
def test_login_response_includes_role(client):
  """로그인하면 응답에 등급이 담겨야 화면이 메뉴를 그릴 수 있다."""
  register(client, 'u1')
  res = client.post('/api/auth/login', json={'username': 'u1', 'password': PW})

  assert res.status_code == 200
  assert res.get_json()['role'] == 'user'      # 가입 기본 등급


def test_me_requires_login(client):
  """로그인 없이 내 정보를 물으면 401."""
  assert client.get('/api/auth/me').status_code == 401


def test_me_returns_username_and_role(client):
  register(client, 'u2')
  res = client.get('/api/auth/me', headers=auth(login(client, 'u2')))

  assert res.status_code == 200
  body = res.get_json()
  assert body['username'] == 'u2'
  assert body['role'] == 'user'


# ── 골드 전용 API — 계층 검사 ────────────────────────────
def test_gold_api_rejects_anonymous(client):
  """비로그인은 401(인증 없음)."""
  assert client.get('/api/gold/posts').status_code == 401


def test_gold_api_rejects_plain_user(client):
  """로그인했어도 등급이 모자라면 403(인가 부족)."""
  register(client, 'plain')
  res = client.get('/api/gold/posts', headers=auth(login(client, 'plain')))

  assert res.status_code == 403
  body = res.get_json()
  assert body['required_role'] == 'gold'       # 화면이 예외 안내에 쓴다
  assert body['current_role'] == 'user'


def test_gold_api_allows_gold(client):
  register(client, 'goldie')
  set_role(client, 'goldie', 'gold')

  assert client.get('/api/gold/posts',
                    headers=auth(login(client, 'goldie'))).status_code == 200


def test_gold_api_allows_admin_by_hierarchy(client):
  """admin > gold 이므로 관리자도 골드 화면을 볼 수 있다."""
  register(client, 'boss')
  set_role(client, 'boss', 'admin')

  assert client.get('/api/gold/posts',
                    headers=auth(login(client, 'boss'))).status_code == 200


def test_gold_api_returns_only_gold_category(app, client):
  """골드 전용 게시글만 골라 준다."""
  register(client, 'goldie2')
  set_role(client, 'goldie2', 'gold')
  with app.app_context():
    uid = User.query.filter_by(username='goldie2').first().id
    db.session.add_all([
        Post(title='일반글', content='c', category='일반', author_id=uid),
        Post(title='골드글', content='c', category='골드', author_id=uid),
    ])
    db.session.commit()

  body = client.get('/api/gold/posts',
                    headers=auth(login(client, 'goldie2'))).get_json()

  assert [p['title'] for p in body['posts']] == ['골드글']
  assert body['count'] == 1


# ── 관리자: 부여 · 회수 ──────────────────────────────────
def test_grant_gold_role(client):
  register(client, 'target')
  res = set_role(client, 'target', 'gold')

  assert res.status_code == 200
  body = res.get_json()
  assert (body['old_role'], body['new_role']) == ('user', 'gold')


def test_grant_rejects_unknown_role(client):
  register(client, 'target2')
  res = set_role(client, 'target2', 'superuser')

  assert res.status_code == 400


def test_admin_can_grant_gold_with_jwt(client):
  """사람(관리자 페이지)은 API 키 없이 admin JWT 로 부여한다."""
  register(client, 'boss2')
  register(client, 'member')
  set_role(client, 'boss2', 'admin')

  res = client.post('/api/admin/grant', headers=auth(login(client, 'boss2')),
                    json={'username': 'member', 'role': 'gold'})

  assert res.status_code == 200
  assert res.get_json()['new_role'] == 'gold'


def test_plain_user_cannot_grant(client):
  """일반 회원이 권한을 스스로 올릴 수 없어야 한다."""
  register(client, 'sneaky')
  res = client.post('/api/admin/grant', headers=auth(login(client, 'sneaky')),
                    json={'username': 'sneaky', 'role': 'admin'})

  assert res.status_code == 401


def test_revoke_gold_back_to_user(client):
  register(client, 'demote')
  set_role(client, 'demote', 'gold')

  res = client.post('/api/admin/revoke', headers=KEY,
                    json={'username': 'demote', 'reason': '테스트 회수'})

  assert res.status_code == 200
  body = res.get_json()
  assert (body['old_role'], body['new_role'], body['revoked']) == \
         ('gold', 'user', True)


def test_revoked_gold_loses_access(client):
  """회수 뒤에는 골드 API 가 다시 막혀야 한다."""
  register(client, 'demote2')
  set_role(client, 'demote2', 'gold')
  client.post('/api/admin/revoke', headers=KEY, json={'username': 'demote2'})

  assert client.get('/api/gold/posts',
                    headers=auth(login(client, 'demote2'))).status_code == 403


def test_admin_users_list_shows_gold(client):
  register(client, 'g1')
  set_role(client, 'g1', 'gold')

  body = client.get('/api/admin/users?role=gold', headers=KEY).get_json()

  assert [u['username'] for u in body['users']] == ['g1']


def test_gold_users_are_not_policy_violations(client):
  """정책 위반은 '허용목록 밖 admin' 만. gold 는 위반이 아니다."""
  register(client, 'g2')
  set_role(client, 'g2', 'gold')

  body = client.get('/api/admin/violations', headers=KEY).get_json()

  assert body['count'] == 0


# ── 화면 라우트 ─────────────────────────────────────────
def test_gold_page_route_exists(client):
  """페이지는 항상 렌더되고, 등급 차단은 화면 JS 가 담당한다."""
  assert client.get('/gold').status_code == 200
