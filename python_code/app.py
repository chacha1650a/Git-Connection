from flask import Flask, render_template_string, Response
import pymysql
import json

app = Flask(__name__)

def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='123456',
        database='github_db',
        cursorclass=pymysql.cursors.DictCursor
    )

@app.route('/')
def index():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM api_logs ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
    conn.close()

    html = '''
    <!DOCTYPE html>
    <html>
    <head><title>GitHub API Logs</title></head>
    <body>
        <h1>GitHub API Log Viewer</h1>
        <a href="/download">데이터 파일로 다운로드하기 (JSON)</a>
        <br><br>
        <table border="1" cellpadding="8" style="border-collapse: collapse;">
            <tr><th>ID</th><th>Current User URL</th><th>Gists URL</th><th>Time</th></tr>
            {% for row in rows %}
            <tr>
                <td>{{ row.id }}</td>
                <td>{{ row.current_user_url }}</td>
                <td>{{ row.gists_url }}</td>
                <td>{{ row.created_at }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    '''
    return render_template_string(html, rows=rows)

@app.route('/download')
def download():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM api_logs")
        rows = cursor.fetchall()
    conn.close()

    json_data = json.dumps(rows, ensure_ascii=False, indent=4, default=str)
    return Response(
        json_data,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=github_logs.json"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)