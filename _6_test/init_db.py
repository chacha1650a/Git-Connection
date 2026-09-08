import requests
import pymysql
import json

# 1. 깃허브 API 호출
r = requests.get("https://api.github.com")
data = r.json()

current_user_url = data.get("current_user_url")
gists_url = data.get("gists_url")
raw_json_str = json.dumps(data)

# 2. MySQL 서버 연결 (데이터베이스 지정 없이 먼저 연결)
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='123456',
    charset='utf8mb4'
)

try:
    with connection.cursor() as cursor:
        # 데이터베이스와 테이블이 없으면 자동 생성
        cursor.execute("CREATE DATABASE IF NOT EXISTS github_db;")
        cursor.execute("USE github_db;")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                current_user_url VARCHAR(255),
                gists_url VARCHAR(255),
                raw_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 데이터 삽입
        sql = "INSERT INTO api_logs (current_user_url, gists_url, raw_json) VALUES (%s, %s, %s)"
        cursor.execute(sql, (current_user_url, gists_url, raw_json_str))
        
    connection.commit()
    print("데이터베이스 설정 및 데이터 적재 완료!")
finally:
    connection.close()