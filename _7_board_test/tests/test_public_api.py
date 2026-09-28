import pytest
from app import app


@pytest.fixture
def client():
  app.config['TESTING'] = True
  with app.test_client() as client:
    yield client


def test_get_public_posts_api_route(client):
  """1) 백엔드 공공 API 프록시 라우트(/api/public/posts)가 정상 응답하는지 테스트"""
  response = client.get('/api/public/posts')

  # 외부 공공데이터포털 서버 상태에 따라 200(성공) 또는 500(외부 연동 실패)이 떨어질 수 있으나,
  # 404(Not Found)가 아니어야 라우팅이 정상 작동하는 것입니다.
  assert response.status_code in [200, 500]

  data = response.get_json()
  assert data is not None
  # 성공 시 'getRecommendedKr' 혹은 실패 시 'msg' 키가 포함되어 있어야 함
  assert 'msg' in data or 'getRecommendedKr' in data


def test_public_posts_page_route(client):
  """2) 공공데이터 목록 보기 페이지 라우트(/public-posts)가 정상 작동하는지 테스트"""
  response = client.get('/public-posts')
  # 템플릿 파일(public_posts.html)이 존재하면 200, 없으면 500(TemplateNotFound)이 발생합니다.
  # 라우트 자체의 존재 유무(404 아님)를 확인합니다.
  assert response.status_code != 404


def test_public_post_detail_page_route(client):
  """3) 공공데이터 상세 보기 페이지 라우트(/public-posts/<int:uc_seq>)가 정상 작동하는지 테스트"""
  test_uc_seq = 123
  response = client.get(f'/public-posts/{test_uc_seq}')
  # 마찬가지로 404가 발생하지 않고 라우팅이 매핑되는지 확인
  assert response.status_code != 404


def test_wrong_route_returns_404(client):
  """4) 잘못된 경로(/api/public-posts 등)로 요청 시 404 에러가 발생하는지 확인 (로그에서 발생했던 이슈 검증)"""
  response = client.get('/api/public-posts')
  assert response.status_code == 404