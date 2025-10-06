import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template_string, flash, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "golos-klassa-secret")

DB_PATH = 'ideas.db'
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "school123")

# --- HTML + CSS как строки ---
BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Голос класса</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; margin: 0; padding: 16px; color: #333; }
        .container { max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        h1 { color: #2c3e50; text-align: center; margin-top: 0; }
        textarea { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; resize: vertical; min-height: 80px; }
        button { background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; }
        button:hover { background: #2980b9; }
        .idea { background: #f8f9fa; padding: 16px; margin: 16px 0; border-radius: 10px; border-left: 4px solid #3498db; }
        .admin-idea { border-left-color: #e74c3c; }
        .meta { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; font-size: 14px; color: #666; }
        .meta a { color: #e74c3c; text-decoration: none; font-weight: bold; }
        .meta a:hover { text-decoration: underline; }
        @media (max-width: 600px) { .container { padding: 16px; } .meta { flex-direction: column; gap: 6px; } button { padding: 14px; } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🗣️ Голос класса</h1>
        <p>Анонимно предлагай идеи и голосуй за лучшие!</p>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}<p style="color:red;">{{ msg }}</p>{% endfor %}
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </div>
</body>
</html>
'''

INDEX_PAGE = BASE_TEMPLATE.replace(
    '{% block content %}{% endblock %}',
    '''
    <form method="POST" action="/add">
        <textarea name="text" placeholder="Напиши свою идею (до 200 символов)..." maxlength="200" required></textarea>
        <button type="submit">➕ Добавить идею</button>
    </form>
    <hr>
    <h2>Идеи (по голосам)</h2>
    {% if ideas %}
        {% for idea in ideas %}
        <div class="idea">
            <p>{{ idea.text }}</p>
            <div class="meta">
                <span>Голосов: {{ idea.votes }}</span>
                <a href="{{ url_for('vote', idea_id=idea.id) }}">✅ Поддержать</a>
            </div>
        </div>
        {% endfor %}
    {% else %}
        <p>Пока нет идей. Будь первым!</p>
    {% endif %}
    '''
)

ADMIN_PAGE = BASE_TEMPLATE.replace(
    '{% block content %}{% endblock %}',
    '''
    <h2>🔐 Админка — Управление идеями</h2>
    <p>Только для администрации школы.</p>
    {% if ideas %}
      {% for idea in ideas %}
      <div class="idea admin-idea">
        <p><strong>{{ idea.text }}</strong></p>
        <div class="meta">
          <span>IP автора: {{ idea.ip }}</span>
          <span>Голосов: {{ idea.votes }}</span>
          <span>Добавлено: {{ idea.created_at }}</span>
          <a href="/admin/delete/{{ idea.id }}?password={{ password }}" onclick="return confirm('Удалить идею?')">🗑️ Удалить</a>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <p>Нет идей.</p>
    {% endif %}
    <a href="{{ url_for('index') }}">← Вернуться на главную</a>
    '''
)

# --- База данных ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ideas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            ip TEXT NOT NULL,
            votes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            idea_id INTEGER,
            ip TEXT,
            PRIMARY KEY (idea_id, ip)
        )
    ''')
    conn.commit()
    conn.close()

# --- Роуты ---
@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, text, votes FROM ideas ORDER BY votes DESC, created_at DESC")
    ideas = c.fetchall()
    conn.close()
    return render_template_string(INDEX_PAGE, ideas=ideas, url_for=url_for)

@app.route('/add', methods=['POST'])
def add_idea():
    text = request.form.get('text', '').strip()
    if text and len(text) <= 200:
        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO ideas (text, ip) VALUES (?, ?)", (text, user_ip))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/vote/<int:idea_id>')
def vote(idea_id):
    user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM votes WHERE idea_id = ? AND ip = ?", (idea_id, user_ip))
    if not c.fetchone():
        c.execute("UPDATE ideas SET votes = votes + 1 WHERE id = ?", (idea_id,))
        c.execute("INSERT INTO votes (idea_id, ip) VALUES (?, ?)", (idea_id, user_ip))
        conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/admin')
def admin_panel():
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        flash("Неверный пароль!")
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM ideas ORDER BY created_at DESC")
    ideas = c.fetchall()
    conn.close()
    return render_template_string(ADMIN_PAGE, ideas=ideas, password=password, url_for=url_for)

@app.route('/admin/delete/<int:idea_id>')
def delete_idea(idea_id):
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM ideas WHERE id = ?", (idea_id,))
    c.execute("DELETE FROM votes WHERE idea_id = ?", (idea_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel', password=password))

# --- Запуск ---
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)