import os
import sqlite3
import base64
import re
from flask import Flask, request, redirect, render_template_string, send_file
import tempfile

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "render-secret-key")

DB_PATH = 'ideas.db'
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "school123")
MAX_IMAGE_SIZE = 2 * 1024 * 1024

# --- Мат и 18+ ---
BAD_WORDS = {
    'бля', 'бляд', 'еб', 'ёб', 'хуй', 'пизд', 'сука', 'суч', 'нахуй', 'нахер', 'охуел', 'охуев', 'ахуеть',
    'гандон', 'говно', 'дроч', 'ебал', 'ебан', 'ебаш', 'залуп', 'мудил', 'мудоз', 'пидор', 'педик', 'пидар',
    'срать', 'ссать', 'трах', 'чмо', 'шлюх', 'шалав', 'урод', 'скотина', 'мерзавец', 'гад', 'сволочь',
    'порно', 'секс', 'интим', 'эротик', 'голый', 'обнаж', 'нюд', 'nude', 'porn', 'xxx', 'sex', 'boobs', 'dick',
    'жестоко', 'убить', 'смерть', 'повеситься', 'суицид', 'наркотик', 'марихуан', 'амфетамин', 'кокаин',
    'оружие', 'бомба', 'взорвать', 'террор', 'кровь', 'резать', 'нож', 'пистолет', 'насиль', 'изнасил'
}

def contains_bad_words(text):
    if not text:
        return False
    clean = re.sub(r'[^а-яa-z\s]', '', text.lower())
    words = clean.split()
    for word in words:
        for bad in BAD_WORDS:
            if bad in word:
                return True
    return False

def get_real_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr or '127.0.0.1'
    return ip

# --- Инициализация БД ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ideas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            ip TEXT NOT NULL,
            image_data TEXT,
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
    c.execute('''
        CREATE TABLE IF NOT EXISTS replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idea_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            ip TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (idea_id) REFERENCES ideas(id) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

# --- Обработка фото ---
def process_image(file):
    if not file or not file.filename:
        return None
    ext = file.filename.lower().split('.')[-1]
    if ext not in {'png', 'jpg', 'jpeg', 'gif', 'webp'}:
        return None
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_IMAGE_SIZE:
        return None
    try:
        data = file.read()
        b64 = base64.b64encode(data).decode('utf-8')
        mime = 'image/jpeg' if ext in {'jpg', 'jpeg'} else \
               'image/png' if ext == 'png' else \
               'image/gif' if ext == 'gif' else 'image/webp'
        return f"{mime};base64,{b64}"
    except:
        return None

# --- Скачивание фото (публичное) ---
@app.route('/download/<int:idea_id>')
def download_image(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT image_data FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    conn.close()

    if not idea or not idea['image_data']:
        return "Фото не найдено", 404

    try:
        header, b64data = idea['image_data'].split(',', 1)
        mime = header.split(';')[0]
        ext = mime.split('/')[1] if '/' in mime else 'jpg'
        filename = f"idea_{idea_id}.{ext}"

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{ext}") as tmp:
            tmp.write(base64.b64decode(b64data))
            return send_file(tmp.name, as_attachment=True, download_name=filename)
    except Exception as e:
        return f"Ошибка: {e}", 500

# --- HTML: главная ---
def get_index_html(ideas_with_replies):
    content = ""
    for idea in ideas_with_replies:
        img = f'<img src="{idea["image_data"]}" class="idea-img">' if idea["image_data"] else ""
        download_btn = f' <a href="/download/{idea["id"]}" class="download-btn">💾 Скачать</a>' if idea["image_data"] else ""
        
        replies_html = ""
        for reply in idea.get("replies", []):
            replies_html += f'<div class="reply"><p>{reply["text"]}</p></div>'

        content += f'''
        <div class="idea">
            {img}
            <p>{idea["text"]}</p>
            {download_btn}
            <div class="meta">
                <span>Голосов: {idea["votes"]}</span>
                <a href="/vote/{idea["id"]}">✅ Поддержать</a>
            </div>
            <div class="replies">
                {replies_html}
                <form method="POST" action="/reply" class="reply-form">
                    <input type="hidden" name="idea_id" value="{idea["id"]}">
                    <input type="text" name="text" placeholder="Ваш ответ (до 150 символов)..." maxlength="150" required>
                    <button type="submit">📨 Ответить</button>
                </form>
            </div>
        </div>
        '''
    return f'''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Голос класса</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; margin: 0; padding: 16px; color: #333; }}
            .container {{ max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
            h1 {{ color: #2c3e50; text-align: center; margin-top: 0; }}
            textarea, input[type="text"] {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; resize: vertical; }}
            button {{ background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; }}
            .idea {{ background: #f8f9fa; padding: 16px; margin: 16px 0; border-radius: 10px; border-left: 4px solid #3498db; }}
            .idea-img {{ max-width: 100%; height: auto; border-radius: 8px; margin-bottom: 10px; display: block; }}
            .download-btn {{ font-size: 14px; color: #27ae60; text-decoration: none; }}
            .replies {{ margin-top: 15px; border-top: 1px dashed #ddd; padding-top: 15px; }}
            .reply {{ background: #e8f4fc; padding: 10px; border-radius: 6px; margin: 8px 0; font-style: italic; color: #2980b9; }}
            .reply-form {{ display: flex; gap: 10px; margin-top: 10px; }}
            .reply-form input {{ flex: 1; }}
            .reply-form button {{ padding: 10px 15px; font-size: 14px; }}
            .meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; font-size: 14px; color: #666; }}
            .meta a {{ color: #27ae60; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🗣️ Голос класса</h1>
            <p>Анонимно предлагай идеи, отвечай и скачивай фото!</p>
            <form method="POST" action="/add" enctype="multipart/form-data">
                <textarea name="text" placeholder="Напиши идею (до 200 символов)..." maxlength="200" required></textarea>
                <input type="file" name="image" accept="image/*">
                <button type="submit">➕ Добавить идею</button>
            </form>
            <hr>
            <h2>Идеи (по голосам)</h2>
            {content if content else "<p>Пока нет идей. Будь первым!</p>"}
        </div>
    </body>
    </html>
    '''

# --- Админка (только удаление) ---
def get_admin_html(ideas, password):
    content = ""
    for idea in ideas:
        img = f'<img src="{idea["image_data"]}" class="admin-img">' if idea["image_data"] else "<span>Нет фото</span>"
        location = "Сервер Render"  # Геолокацию убрали для простоты
        content += f'''
        <div class="idea">
            {img}
            <p><strong>{idea["text"]}</strong></p>
            <div class="meta">
                <span>IP: {idea["ip"]}</span>
                <span>Голосов: {idea["votes"]}</span>
                <a href="/admin/delete/idea/{idea["id"]}?password={password}" onclick="return confirm('Удалить идею и ответы?')">🗑️ Удалить идею</a>
            </div>
        </div>
        '''
    return f'''
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><title>Админка</title></head>
    <body>
        <h2>Админка — удаление</h2>
        {content}
        <a href="/">← Назад</a>
    </body>
    </html>
    '''

# --- Роуты ---
@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = conn.execute("SELECT id, text, votes, image_data FROM ideas ORDER BY votes DESC, created_at DESC").fetchall()
    ideas_with_replies = []
    for idea in ideas:
        replies = conn.execute("SELECT text FROM replies WHERE idea_id = ? ORDER BY created_at ASC", (idea["id"],)).fetchall()
        ideas_with_replies.append({
            "id": idea["id"],
            "text": idea["text"],
            "votes": idea["votes"],
            "image_data": idea["image_data"],
            "replies": [dict(r) for r in replies]
        })
    conn.close()
    return get_index_html(ideas_with_replies)

@app.route('/add', methods=['POST'])
def add_idea():
    text = request.form.get('text', '').strip()
    if not text or len(text) > 200 or contains_bad_words(text):
        return redirect('/')
    user_ip = get_real_ip()
    image_data = process_image(request.files.get('image'))
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO ideas (text, ip, image_data) VALUES (?, ?, ?)", (text, user_ip, image_data))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/reply', methods=['POST'])
def add_reply():
    text = request.form.get('text', '').strip()
    idea_id = request.form.get('idea_id')
    if not text or len(text) > 150 or contains_bad_words(text) or not idea_id:
        return redirect('/')
    user_ip = get_real_ip()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO replies (idea_id, text, ip) VALUES (?, ?, ?)", (idea_id, text, user_ip))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/vote/<int:idea_id>')
def vote(idea_id):
    user_ip = get_real_ip()
    conn = sqlite3.connect(DB_PATH)
    exists = conn.execute("SELECT 1 FROM votes WHERE idea_id = ? AND ip = ?", (idea_id, user_ip)).fetchone()
    if not exists:
        conn.execute("UPDATE ideas SET votes = votes + 1 WHERE id = ?", (idea_id,))
        conn.execute("INSERT INTO votes (idea_id, ip) VALUES (?, ?)", (idea_id, user_ip))
        conn.commit()
    conn.close()
    return redirect('/')

# --- Админка: только удаление ---
@app.route('/admin')
def admin_panel():
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = conn.execute("SELECT * FROM ideas ORDER BY created_at DESC").fetchall()
    conn.close()
    return get_admin_html([dict(i) for i in ideas], password)

@app.route('/admin/delete/idea/<int:idea_id>')
def delete_idea(idea_id):
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM ideas WHERE id = ?", (idea_id,))
    # Ответы удалятся автоматически благодаря ON DELETE CASCADE
    conn.commit()
    conn.close()
    return redirect(f'/admin?password={password}')

# --- Запуск ---
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)