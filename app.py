import os
import sqlite3
import base64
import re
from flask import Flask, request, redirect, render_template_string, send_file, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "render-secret-key")

DB_PATH = 'ideas.db'
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "school123")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

THEMES = ["Школа", "Мероприятия", "Питание", "Спорт", "Учёба", "Другое"]

BAD_WORDS = {
    'бля', 'бляд', 'еб', 'ёб', 'хуй', 'пизд', 'сука', 'суч', 'нахуй', 'нахер', 'охуел', 'охуев', 'ахуеть',
    'гандон', 'говно', 'дроч', 'ебал', 'ебан', 'ебаш', 'залуп', 'мудил', 'мудоз', 'пидор', 'педик', 'пидар',
    'срать', 'ссать', 'трах', 'чмо', 'шлюх', 'шалав', 'урод', 'скотина', 'мерзавец', 'гад', 'сволочь', 'мразь',
    'лох', 'лошара', 'тварь', 'животное', 'идиот', 'дурак', 'придурок', 'кретин', 'мудак', 'уродина',
    'порно', 'секс', 'интим', 'эротик', 'голый', 'обнаж', 'нюд', 'nude', 'porn', 'xxx', 'sex', 'boobs', 'dick', 'pussy',
    'жестоко', 'убить', 'смерть', 'повеситься', 'суицид', 'наркотик', 'марихуан', 'амфетамин', 'кокаин', 'героин',
    'оружие', 'бомба', 'взорвать', 'террор', 'кровь', 'резать', 'нож', 'пистолет', 'насиль', 'изнасил', 'драка',
    'бот', 'спам', 'лох', 'дурачок', 'тупой', 'нищеброд', 'засранец', 'флуд', 'тролль', 'хейт', 'бред', 'чушь'
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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ideas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL,
            theme TEXT NOT NULL,
            custom_theme TEXT,
            file_data TEXT,
            file_name TEXT,
            file_mime TEXT,
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

def process_file(file, is_image=False, is_video=False):
    if not file or not file.filename:
        return None, None, None
    filename = file.filename
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE:
        return None, None, None
    try:
        data = file.read()
        b64 = base64.b64encode(data).decode('utf-8')
        ext = filename.lower().split('.')[-1]
        if is_image:
            mime = 'image/jpeg' if ext in {'jpg','jpeg'} else \
                   'image/png' if ext == 'png' else \
                   'image/gif' if ext == 'gif' else 'image/webp'
        elif is_video:
            mime = 'video/mp4' if ext == 'mp4' else 'video/webm'
        else:
            mime_map = {
                'pdf': 'application/pdf',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'txt': 'text/plain',
                'zip': 'application/zip'
            }
            mime = mime_map.get(ext, 'application/octet-stream')
        # ВАЖНО: используем Data URL с префиксом "data:"
        return f"data:{mime};base64,{b64}", filename, mime
    except Exception as e:
        print(f"Ошибка обработки файла: {e}")
        return None, None, None

@app.route('/download/<int:idea_id>')
def download_file(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT file_data, file_name FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    conn.close()
    if not idea or not idea['file_data']:
        abort(404)
    try:
        # Разделяем по первой запятой — вдруг есть "data:..." в начале
        if idea['file_data'].startswith('data:'):
            header, b64data = idea['file_data'].split(',', 1)
        else:
            # Поддержка старых записей без "data:" (на всякий случай)
            b64data = idea['file_data']
        filename = idea['file_name'] or f"file_{idea_id}"
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(base64.b64decode(b64data))
            return send_file(tmp.name, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Ошибка скачивания: {e}")
        abort(400)

@app.errorhandler(404)
def not_found(e):
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>404 — Не найдено</title></head>
    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>404</h1>
        <p>Идея не найдена.</p>
        <a href="/">← Вернуться на главную</a>
    </body>
    </html>
    '''), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>400 — Ошибка</title></head>
    <body style="font-family: sans-serif; text-align: center; padding: 50px;">
        <h1>400</h1>
        <p>Некорректный запрос.</p>
        <a href="/">← Вернуться на главную</a>
    </body>
    </html>
    '''), 400

@app.route('/')
def index():
    query = request.args.get('q', '').strip()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    if query:
        sql = """
            SELECT id, text, theme, custom_theme, votes, file_mime, file_data
            FROM ideas 
            WHERE text LIKE ? OR theme LIKE ? OR custom_theme LIKE ?
            ORDER BY votes DESC, created_at DESC
        """
        like_term = f"%{query}%"
        ideas = conn.execute(sql, (like_term, like_term, like_term)).fetchall()
    else:
        ideas = conn.execute("""
            SELECT id, text, theme, custom_theme, votes, file_mime, file_data
            FROM ideas 
            ORDER BY votes DESC, created_at DESC
        """).fetchall()
    
    conn.close()
    
    ideas_html = ""
    for idea in ideas:
        theme = idea["custom_theme"] if idea["theme"] == "Другое" and idea["custom_theme"] else idea["theme"]
        media = ""
        if idea["file_data"]:
            if idea["file_mime"] and idea["file_mime"].startswith('image/'):
                media = f'<img src="{idea["file_data"]}" class="media-preview">'
            elif idea["file_mime"] and idea["file_mime"].startswith('video/'):
                media = f'<video controls playsinline class="media-preview" src="{idea["file_data"]}"></video>'
        
        ideas_html += f'''
        <div class="idea-card">
            <div class="theme-badge">{theme}</div>
            {media}
            <h3>{idea["text"][:100]}{"..." if len(idea["text"]) > 100 else ""}</h3>
            <div class="meta">
                <span>Голосов: {idea["votes"]}</span>
                <a href="/vote/{idea["id"]}">✅ Поддержать</a>
                <a href="/ideas/{idea["id"]}">Подробнее →</a>
            </div>
        </div>
        '''
    
    search_form = f'''
    <form method="GET" style="margin: 20px 0;">
        <input type="text" name="q" value="{query}" placeholder="Поиск по идеям и темам..." 
               style="width:100%; padding:12px; border:1px solid #ddd; border-radius:8px; font-size:16px;">
        <button type="submit" style="margin-top:10px; width:100%; padding:12px; background:#3498db; color:white; border:none; border-radius:8px; cursor:pointer;">
            🔍 Найти
        </button>
        {"<div style='margin-top:10px;'><a href='/' style='color:#3498db; text-decoration:underline;'>Показать все идеи</a></div>" if query else ""}
    </form>
    '''
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Голос класса</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; margin: 0; padding: 16px; color: #333; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
            h1 {{ color: #2c3e50; text-align: center; }}
            .idea-card {{ background: #f8f9fa; padding: 16px; margin: 16px 0; border-radius: 10px; border-left: 4px solid #3498db; }}
            .theme-badge {{ display: inline-block; background: #3498db; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin-bottom: 10px; }}
            .media-preview {{ max-width: 100%; height: auto; border-radius: 8px; margin: 10px 0; display: block; }}
            .meta {{ display: flex; justify-content: space-between; margin-top: 10px; font-size: 14px; color: #666; }}
            .meta a {{ color: #3498db; text-decoration: none; font-weight: bold; }}
            form {{ margin: 20px 0; }}
            select, input[type="text"], textarea, button {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; }}
            button {{ background: #3498db; color: white; border: none; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🗣️ Голос класса</h1>
            <p style="font-size:14px; color:#e74c3c;">⚠️ Файлы могут удаляться при простое сайта. Не загружайте важные документы!</p>
            
            {search_form}
            
            <form method="POST" action="/add" enctype="multipart/form-data">
                <select name="theme" required onchange="toggleCustomTheme()">
                    <option value="">Выберите тему</option>
                    {''.join(f'<option value="{t}">{t}</option>' for t in THEMES)}
                </select>
                <input type="text" name="custom_theme" id="customTheme" placeholder="Ваша тема..." style="display:none;">
                
                <textarea name="text" placeholder="Ваша идея (до 200 символов)..." maxlength="200" required></textarea>
                
                <input type="file" name="image" accept="image/*" style="display:none;" id="imageInput">
                <input type="file" name="video" accept="video/mp4,video/webm" style="display:none;" id="videoInput">
                <input type="file" name="file" accept="*/*" style="display:none;" id="fileInput">
                
                <div style="display:flex; flex-wrap:wrap; gap:8px; margin:12px 0;">
                    <button type="button" onclick="document.getElementById('imageInput').click()">📷 Фото</button>
                    <button type="button" onclick="document.getElementById('videoInput').click()">🎥 Видео</button>
                    <button type="button" onclick="document.getElementById('fileInput').click()">📎 Любой файл</button>
                </div>
                
                <button type="submit">➕ Добавить идею</button>
            </form>
            <hr>
            <h2>Идеи {"по запросу: " + query if query else ""}</h2>
            {ideas_html if ideas_html else "<p>Ничего не найдено.</p>" if query else "<p>Пока нет идей.</p>"}
        </div>
        <script>
            function toggleCustomTheme() {{
                const select = document.querySelector('select[name="theme"]');
                const custom = document.getElementById('customTheme');
                custom.style.display = select.value === 'Другое' ? 'block' : 'none';
                if (select.value !== 'Другое') custom.value = '';
            }}
            document.getElementById('imageInput').addEventListener('change', function(e) {{
                if (e.target.files.length > 0) {{
                    document.getElementById('videoInput').value = '';
                    document.getElementById('fileInput').value = '';
                }}
            }});
            document.getElementById('videoInput').addEventListener('change', function(e) {{
                if (e.target.files.length > 0) {{
                    document.getElementById('imageInput').value = '';
                    document.getElementById('fileInput').value = '';
                }}
            }});
            document.getElementById('fileInput').addEventListener('change', function(e) {{
                if (e.target.files.length > 0) {{
                    document.getElementById('imageInput').value = '';
                    document.getElementById('videoInput').value = '';
                }}
            }});
        </script>
    </body>
    </html>
    ''')

@app.route('/ideas/<int:idea_id>')
def idea_detail(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT * FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    if not idea:
        abort(404)
    replies = conn.execute("SELECT text FROM replies WHERE idea_id = ? ORDER BY created_at ASC", (idea_id,)).fetchall()
    conn.close()
    
    theme = idea["custom_theme"] if idea["theme"] == "Другое" and idea["custom_theme"] else idea["theme"]
    media = ""
    download_btn = f'<a href="/download/{idea_id}" class="download-btn">💾 Скачать файл</a>'
    
    if idea["file_data"]:
        if idea["file_mime"] and idea["file_mime"].startswith('image/'):
            media = f'<img src="{idea["file_data"]}" class="media-preview">'
        elif idea["file_mime"] and idea["file_mime"].startswith('video/'):
            media = f'<video controls playsinline class="media-preview" src="{idea["file_data"]}"></video>'
    
    replies_html = "".join(f'<div class="reply">{r["text"]}</div>' for r in replies)
    
    return render_template_string(f'''
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{theme} — Голос класса</title>
        <style>
            * {{ box-sizing: border-box; }}
            body {{ font-family: sans-serif; background: #f9f9f9; padding: 16px; }}
            .container {{ max-width: 700px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
            .theme-badge {{ background: #3498db; color: white; padding: 4px 8px; border-radius: 4px; display: inline-block; margin-bottom: 10px; }}
            .media-preview {{ max-width: 100%; height: auto; border-radius: 8px; margin: 15px 0; display: block; }}
            .download-btn {{ color: #27ae60; text-decoration: none; font-weight: bold; }}
            .reply {{ background: #e8f4fc; padding: 10px; border-radius: 6px; margin: 8px 0; color: #2980b9; }}
            form {{ margin-top: 20px; }}
            input[type="text"], button {{ padding: 10px; font-size: 16px; width: 100%; margin-top: 10px; }}
            button {{ background: #3498db; color: white; border: none; border-radius: 6px; cursor: pointer; }}
            .back {{ margin-top: 20px; display: block; color: #3498db; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/" class="back">← Все идеи</a>
            <div class="theme-badge">{theme}</div>
            <h2>{idea["text"]}</h2>
            {media}
            {download_btn}
            <p><strong>Голосов за идею:</strong> {idea["votes"]}</p>
            <h3>Ответы ({len(replies)})</h3>
            {replies_html}
            <form method="POST" action="/reply">
                <input type="hidden" name="idea_id" value="{idea_id}">
                <input type="text" name="text" placeholder="Ваш ответ (до 150 символов)..." maxlength="150" required>
                <button type="submit">📨 Ответить</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/add', methods=['POST'])
def add_idea():
    text = request.form.get('text', '').strip()
    theme = request.form.get('theme', '').strip()
    custom_theme = request.form.get('custom_theme', '').strip() if theme == "Другое" else ""
    if not text or len(text) > 200 or not theme or theme not in THEMES or contains_bad_words(text):
        abort(400)
    if theme == "Другое" and (not custom_theme or len(custom_theme) > 50 or contains_bad_words(custom_theme)):
        abort(400)
    
    user_ip = get_real_ip()
    file_data, file_name, file_mime = None, None, None

    if 'image' in request.files and request.files['image'].filename:
        file_data, file_name, file_mime = process_file(request.files['image'], is_image=True)
    elif 'video' in request.files and request.files['video'].filename:
        file_data, file_name, file_mime = process_file(request.files['video'], is_video=True)
    elif 'file' in request.files and request.files['file'].filename:
        file_data, file_name, file_mime = process_file(request.files['file'])

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ideas (text, theme, custom_theme, file_data, file_name, file_mime, ip) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (text, theme, custom_theme, file_data, file_name, file_mime, user_ip))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/reply', methods=['POST'])
def add_reply():
    text = request.form.get('text', '').strip()
    idea_id = request.form.get('idea_id')
    if not text or len(text) > 150 or not idea_id or contains_bad_words(text):
        abort(400)
    user_ip = get_real_ip()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO replies (idea_id, text, ip) VALUES (?, ?, ?)", (idea_id, text, user_ip))
    conn.commit()
    conn.close()
    return redirect(f'/ideas/{idea_id}')

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

# Админка
@app.route('/admin')
def admin_panel():
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = conn.execute("SELECT * FROM ideas ORDER BY created_at DESC").fetchall()
    conn.close()
    content = ""
    for idea in ideas:
        theme = idea["custom_theme"] if idea["theme"] == "Другое" else idea["theme"]
        content += f'''
        <div style="border:1px solid #eee; padding:10px; margin:10px 0;">
            <strong>{theme}</strong>: {idea["text"][:50]}...
            <a href="/admin/delete/{idea["id"]}?password={password}" onclick="return confirm('Удалить?')">🗑️</a>
        </div>
        '''
    return f'''
    <div style="max-width:800px; margin:0 auto; padding:20px;">
        <h2>Админка</h2>
        {content}
        <a href="/">← Назад</a>
    </div>
    '''

@app.route('/admin/delete/<int:idea_id>')
def delete_idea(idea_id):
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM ideas WHERE id = ?", (idea_id,))
    conn.commit()
    conn.close()
    return redirect(f'/admin?password={password}')

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)