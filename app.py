import os
import sqlite3
import base64
import re
import requests
from flask import Flask, request, redirect, render_template_string, send_file, jsonify
import tempfile

# --- Настройки ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "render-secret-key-for-school")

DB_PATH = 'ideas.db'
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "school123")
MAX_IMAGE_SIZE = 2 * 1024 * 1024  # 2 MB

# --- Список запрещённых слов ---
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
    """Надёжное получение IP пользователя на Render"""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr or '127.0.0.1'
    return ip

def get_location_by_ip(ip):
    if ip in ('127.0.0.1', 'localhost', '::1'):
        return "Локальный хост"
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if response.status_code == 200:
            data = response.json()
            city = data.get("city") or "Неизвестно"
            region = data.get("region") or ""
            org = data.get("org") or "Неизвестно"
            return f"{city} ({region}), {org}"
    except:
        pass
    return "Не удалось определить"

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
            reply TEXT,  -- ответ от админа
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

# --- Обработка изображения ---
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

# --- Сохранение фото во временный файл для скачивания ---
@app.route('/download/<int:idea_id>')
def download_image(idea_id):
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return "Доступ запрещён", 403

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
def get_index_html(ideas):
    ideas_html = ""
    for idea in ideas:
        img = f'<img src="{idea["image_data"]}" class="idea-img">' if idea["image_data"] else ""
        reply = f'<div class="reply">💬 Ответ: {idea["reply"]}</div>' if idea["reply"] else ""
        ideas_html += f'''
        <div class="idea">
            {img}
            <p>{idea["text"]}</p>
            {reply}
            <div class="meta">
                <span>Голосов: {idea["votes"]}</span>
                <a href="/vote/{idea["id"]}">✅ Поддержать</a>
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
            textarea {{ width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; resize: vertical; min-height: 80px; }}
            button {{ background: #3498db; color: white; border: none; padding: 12px 20px; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; margin-top: 10px; }}
            input[type="file"] {{ margin: 10px 0; width: 100%; }}
            .idea {{ background: #f8f9fa; padding: 16px; margin: 16px 0; border-radius: 10px; border-left: 4px solid #3498db; }}
            .idea-img {{ max-width: 100%; height: auto; border-radius: 8px; margin-bottom: 10px; display: block; }}
            .reply {{ background: #e8f4fc; padding: 8px; border-radius: 6px; margin: 10px 0; font-style: italic; color: #2980b9; }}
            .meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; font-size: 14px; color: #666; }}
            .meta a {{ color: #27ae60; text-decoration: none; font-weight: bold; }}
            .footer {{ margin-top: 30px; font-size: 12px; color: #777; text-align: center; }}
            .footer a {{ color: #777; text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🗣️ Голос класса</h1>
            <p>Анонимно предлагай идеи и прикрепляй фото! Запрещены: мат, 18+, агрессия.</p>
            <form method="POST" action="/add" enctype="multipart/form-data">
                <textarea name="text" placeholder="Напиши свою идею (до 200 символов)..." maxlength="200" required></textarea>
                <input type="file" name="image" accept="image/*">
                <button type="submit">➕ Добавить идею</button>
            </form>
            <hr>
            <h2>Идеи (по голосам)</h2>
            {ideas_html if ideas_html else "<p>Пока нет идей. Будь первым!</p>"}
            <div class="footer">
                <a href="/privacy">Политика конфиденциальности</a>
            </div>
        </div>
    </body>
    </html>
    '''

# --- HTML: админка ---
def get_admin_html(ideas, password):
    ideas_html = ""
    for idea in ideas:
        img = f'<img src="{idea["image_data"]}" class="admin-img">' if idea["image_data"] else "<span>Нет фото</span>"
        location = get_location_by_ip(idea["ip"])
        download_link = f' | <a href="/download/{idea["id"]}?password={password}">💾 Скачать фото</a>' if idea["image_data"] else ""
        reply_input = f'''
        <form method="POST" action="/admin/reply" style="margin-top:8px;">
            <input type="hidden" name="idea_id" value="{idea["id"]}">
            <input type="hidden" name="password" value="{password}">
            <input type="text" name="reply" placeholder="Ответ на идею..." value="{idea["reply"] or ""}" style="width:60%; padding:5px; font-size:14px;">
            <button type="submit" style="padding:5px 10px; font-size:14px;">📨 Отправить ответ</button>
        </form>
        '''
        ideas_html += f'''
        <div class="idea">
            {img}
            <p><strong>{idea["text"]}</strong></p>
            <div class="meta">
                <span>IP: {idea["ip"]}</span>
                <span>📍 {location}</span>
                <span>Голосов: {idea["votes"]}</span>
                <a href="/admin/delete/{idea["id"]}?password={password}" onclick="return confirm('Удалить?')">🗑️ Удалить</a>
                {download_link}
            </div>
            {reply_input}
        </div>
        '''
    return f'''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Админка — Голос класса</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{ font-family: sans-serif; background: #f9f9f9; padding: 16px; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
            .idea {{ background: #fef6f6; padding: 15px; margin: 15px 0; border-radius: 8px; }}
            .admin-img {{ max-width: 200px; height: auto; border: 1px solid #eee; margin: 5px 0; }}
            .meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 8px; font-size: 13px; }}
            .meta a {{ color: #c0392b; text-decoration: none; }}
            input[type="text"] {{ padding: 5px; font-size: 14px; width: 60%; }}
            button {{ padding: 5px 10px; font-size: 14px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Админка (модерация)</h2>
            <p>📍 — местоположение по IP | 💾 — скачать фото | 📨 — ответить публично</p>
            {ideas_html}
            <a href="/">← Назад</a>
        </div>
    </body>
    </html>
    '''

# --- Остальной HTML (privacy, instructions) — без изменений ---
# (для краткости опущен, но в полной версии он есть)

def get_privacy_html():
    return '''...'''  # как в предыдущей версии

def get_instructions_html():
    return '''...'''  # как в предыдущей версии

# --- Роуты ---
@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = [dict(row) for row in conn.execute("SELECT id, text, votes, image_data, reply FROM ideas ORDER BY votes DESC, created_at DESC")]
    conn.close()
    return get_index_html(ideas)

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

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    password = request.args.get('password') or request.form.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = [dict(row) for row in conn.execute("SELECT * FROM ideas ORDER BY created_at DESC")]
    conn.close()
    return get_admin_html(ideas, password)

@app.route('/admin/reply', methods=['POST'])
def admin_reply():
    password = request.form.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    idea_id = request.form.get('idea_id')
    reply = request.form.get('reply', '').strip()
    if len(reply) > 200:
        reply = reply[:200]
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE ideas SET reply = ? WHERE id = ?", (reply, idea_id))
    conn.commit()
    conn.close()
    return redirect(f'/admin?password={password}')

@app.route('/admin/delete/<int:idea_id>')
def delete_idea(idea_id):
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM ideas WHERE id = ?", (idea_id,))
    conn.execute("DELETE FROM votes WHERE idea_id = ?", (idea_id,))
    conn.commit()
    conn.close()
    return redirect(f'/admin?password={password}')

@app.route('/download/<int:idea_id>')
def download_image_route(idea_id):
    return download_image(idea_id)

@app.route('/privacy')
def privacy():
    return get_privacy_html()

@app.route('/admin/instructions')
def admin_instructions():
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        return redirect('/')
    return get_instructions_html()

# --- Запуск ---
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)