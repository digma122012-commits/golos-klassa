import os
import sqlite3
import base64
import re
import io
import hashlib
from flask import Flask, request, redirect, render_template, send_file, abort

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
def get_fingerprint():
    """Создаёт "отпечаток" устройства на основе доступных данных"""
    ua = request.headers.get('User-Agent', '')
    lang = request.headers.get('Accept-Language', 'en')
    # На Render нет JS, поэтому не можем получить разрешение экрана
    # Используем только User-Agent и язык
    raw = f"{ua}|{lang}"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_ip_hash():
    ip = get_real_ip()
    return hashlib.sha256(ip.encode()).hexdigest()

def is_banned():
    ip_hash = get_ip_hash()
    fingerprint = get_fingerprint()
    conn = sqlite3.connect(DB_PATH)
    ban = conn.execute("""
        SELECT 1 FROM bans 
        WHERE ip_hash = ? AND fingerprint = ?
    """, (ip_hash, fingerprint)).fetchone()
    conn.close()
    return ban is not None

def add_ban(ip_hash, fingerprint, reason=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO bans (ip_hash, fingerprint, reason) VALUES (?, ?, ?)", 
                 (ip_hash, fingerprint, reason))
    conn.commit()
    conn.close()

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
    c.execute('''
        CREATE TABLE IF NOT EXISTS bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        return f"{mime};base64,{b64}", filename, mime
    except Exception as e:
        print(f"Ошибка обработки файла: {e}")
        return None, None, None

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
    return render_template('index.html', ideas=ideas, query=query, themes=THEMES)

@app.route('/ideas/<int:idea_id>')
def idea_detail(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT * FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    if not idea:
        abort(404)
    replies = conn.execute("SELECT text FROM replies WHERE idea_id = ? ORDER BY created_at ASC", (idea_id,)).fetchall()
    conn.close()
    return render_template('idea_detail.html', idea=idea, replies=replies)

@app.route('/preview/<int:idea_id>')
def preview_file(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT file_data, file_mime FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    conn.close()
    if not idea or not idea['file_data']:
        abort(404)
    try:
        header, b64data = idea['file_data'].split(',', 1)
        mime = idea['file_mime'] or 'application/octet-stream'
        data = base64.b64decode(b64data)
        return send_file(io.BytesIO(data), mimetype=mime, as_attachment=False)
    except Exception as e:
        print(f"Ошибка предпросмотра: {e}")
        abort(400)

@app.route('/download/<int:idea_id>')
def download_file(idea_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    idea = conn.execute("SELECT file_data, file_name FROM ideas WHERE id = ?", (idea_id,)).fetchone()
    conn.close()
    if not idea or not idea['file_data']:
        abort(404)
    try:
        header, b64data = idea['file_data'].split(',', 1)
        filename = idea['file_name'] or f"file_{idea_id}"
        data = base64.b64decode(b64data)
        return send_file(io.BytesIO(data), as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Ошибка скачивания: {e}")
        abort(400)

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

@app.route('/admin')
def admin_panel():
    password = request.args.get('password')
    if password != ADMIN_PASSWORD:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ideas = conn.execute("SELECT * FROM ideas ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('admin.html', ideas=ideas, password=password)

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

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message="Идея не найдена."), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, message="Некорректный запрос."), 400

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
