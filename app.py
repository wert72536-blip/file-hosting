import os
import uuid
import hashlib
import secrets
import datetime
import bcrypt
from flask import Flask, request, render_template, send_file, abort, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
from functools import wraps

# ---------- Настройки ----------
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_CONTENT_LENGTH = 1 * 1024 * 1024 * 1024  # 1 ГБ
SECRET_KEY = secrets.token_hex(32)           # !!! Для продакшена замените на постоянную строку и храните в тайне
TOKEN_BYTES = 32                             # длина случайного токена

app = Flask(__name__)
# Теперь берем ключ из настроек Render (Environment Variables)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-key-for-local-dev')
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Rate limiting: защита от брутфорса токенов и чрезмерной загрузки

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"],
    storage_uri="memory://",
)

# ---------- База данных ----------
def init_db():
    conn = sqlite3.connect('files.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        original_name TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        size INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        max_downloads INTEGER NOT NULL DEFAULT 1,
        download_count INTEGER NOT NULL DEFAULT 0,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    # Включаем WAL режим для лучшей конкурентности
    c.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('files.db')
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Вспомогательные функции ----------
def generate_token():
    """Криптостойкий случайный токен для URL"""
    return secrets.token_urlsafe(TOKEN_BYTES)

def hash_token(token):
    """Хэш токена для хранения в БД"""
    return hashlib.sha256(token.encode()).hexdigest()

def is_expired(expires_at):
    return datetime.datetime.fromisoformat(expires_at) < datetime.datetime.utcnow()

def delete_file(file_path):
    try:
        os.remove(file_path)
    except OSError:
        pass

def cleanup_expired():
    """Удаляет просроченные файлы из БД и с диска"""
    conn = get_db()
    now = datetime.datetime.utcnow().isoformat()
    expired = conn.execute('SELECT id, storage_path FROM files WHERE expires_at < ?', (now,)).fetchall()
    for row in expired:
        delete_file(row['storage_path'])
        conn.execute('DELETE FROM files WHERE id = ?', (row['id'],))
    conn.commit()
    conn.close()

# Периодическая очистка: запускаем перед каждым запросом (для простоты, в реальном проекте – фоновая задача)
@app.before_request
def before_request():
    cleanup_expired()

# ---------- Защита от CSRF ----------
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def require_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            token = session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                abort(403, description="Invalid CSRF token")
        return f(*args, **kwargs)
    return decorated

# ---------- Маршруты ----------
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # защита от слишком частой загрузки
@require_csrf
def index():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            return render_template('index.html', error='Файл не выбран')

        # Параметры
        password = request.form.get('password', '').strip()
        max_downloads = request.form.get('max_downloads', '1')
        ttl_hours = request.form.get('ttl_hours', '24')

        try:
            max_downloads = int(max_downloads)
            ttl_hours = int(ttl_hours)
        except ValueError:
            return render_template('index.html', error='Некорректные числовые параметры')

        if max_downloads < 1 or max_downloads > 100:
            max_downloads = 1
        if ttl_hours < 1 or ttl_hours > 168:  # максимум неделя
            ttl_hours = 24

        # Сохраняем файл на диск под случайным именем
        file_id = str(uuid.uuid4())
        original_name = file.filename  # имя без пути, безопасно
        storage_name = file_id
        file_path = os.path.join(UPLOAD_FOLDER, storage_name)
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        # Токен и хэш
        token = generate_token()
        token_hash = hash_token(token)

        # Хэш пароля, если задан
        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=ttl_hours)

        # Сохраняем метаданные в БД
        conn = get_db()
        conn.execute('''INSERT INTO files 
                        (id, original_name, storage_path, size, token_hash, password_hash, max_downloads, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (file_id, original_name, file_path, file_size, token_hash, password_hash, max_downloads, expires_at.isoformat()))
        conn.commit()
        conn.close()

        # Формируем ссылку для получателя
        download_link = url_for('download_page', token=token, _external=True)
        if password:
            download_link += '?pw=1'  # подсказка, что нужен пароль

        return render_template('index.html', success=True, link=download_link, password_set=bool(password))

    return render_template('index.html')

@app.route('/d/<token>', methods=['GET', 'POST'])
@limiter.limit("30 per minute")  # ограничение попыток скачивания
def download_page(token):
    token_hash = hash_token(token)
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE token_hash = ?', (token_hash,)).fetchone()
    if not file_record:
        abort(404, description="Файл не найден или ссылка недействительна")

    if is_expired(file_record['expires_at']):
        conn.close()
        abort(410, description="Срок действия ссылки истёк")

    password_required = file_record['password_hash'] is not None

    if request.method == 'GET':
        # Показываем страницу с информацией о файле и, возможно, формой для пароля
        return render_template('download.html', 
                               file_name=file_record['original_name'],
                               file_size=file_record['size'],
                               password_required=password_required,
                               token=token)
    elif request.method == 'POST':
        # Проверка пароля (если требуется) и отдача файла
        if password_required:
            password = request.form.get('password', '')
            if not bcrypt.checkpw(password.encode('utf-8'), file_record['password_hash'].encode('utf-8')):
                return render_template('download.html',
                                       file_name=file_record['original_name'],
                                       file_size=file_record['size'],
                                       password_required=True,
                                       token=token,
                                       error='Неверный пароль')
        
        # Проверяем лимит скачиваний
        if file_record['download_count'] >= file_record['max_downloads']:
            conn.close()
            abort(410, description="Лимит скачиваний исчерпан")

        # Атомарно увеличиваем счётчик
        conn.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_record['id'],))
        conn.commit()
        conn.close()

        # Отдаём файл
        file_path = file_record['storage_path']
        if not os.path.exists(file_path):
            abort(404, description="Файл был удалён")

        # Безопасная отправка: оригинальное имя экранируется, браузер получит его в заголовке
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_record['original_name'],
            mimetype='application/octet-stream'  # принудительно скачивание, без исполнения
        )

    # На всякий случай
    conn.close()
    abort(405)

# ---------- Заголовки безопасности ----------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    # Content-Security-Policy: разрешаем только свой источник и Bootstrap CDN
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    return response

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)