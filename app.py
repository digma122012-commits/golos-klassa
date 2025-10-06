import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "golos-klassa-secret")

DB_PATH = 'ideas.db'
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "school123")  # Меняй в Render!

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

@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, text, votes FROM ideas ORDER BY votes DESC, created_at DESC")
    ideas = c.fetchall()
    conn.close()
    return render_template('index.html', ideas=ideas)

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

# --- АДМИНКА ---
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
    return render_template('admin.html', ideas=ideas)

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
    return redirect(url_for('admin_panel', password=ADMIN_PASSWORD))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)