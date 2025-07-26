from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
import sqlite3
import hashlib
import os
import httpx
import json
import uuid
import base64
import secrets 
from datetime import datetime
from functools import wraps
from urllib.parse import quote
# --- LIBRARY BARU ---
import midtransclient

app = Flask(__name__, template_folder='.')
app.secret_key = os.urandom(24) 

# --- KONFIGURASI PENTING ---
ADMIN_USERNAME = "vadd"
ADMIN_PASSWORD = "123"
THREE_XUI_PANEL_URL = "https://sg1.vadd.my.id:99/OYrg3Smyrg"
THREE_XUI_USERNAME = "vadd99"
THREE_XUI_PASSWORD = "bismillah33"
SERVER_ADDRESS = "marz.vadd.my.id"
INBOUND_IDS = {"vmess": 7, "trojan": 10}
CONFIG_PRICE = 7000

# --- KONFIGURASI MIDTRANS (MODE PRODUKSI) ---
MIDTRANS_SERVER_KEY = "Mid-server-rEtx_p5Go5EpiW4nX2qshg0E"
MIDTRANS_CLIENT_KEY = "Mid-client-cthx9K42S_sIksKi" 
snap = midtransclient.Snap(
    is_production=True, # Pastikan ini True untuk kunci Produksi
    server_key=MIDTRANS_SERVER_KEY, 
    client_key=MIDTRANS_CLIENT_KEY
)

# --- KELAS API 3X-UI (Tidak Berubah) ---
class ThreeXUIApi:
    def __init__(self, base_url, username, password):
        self.base_url = base_url; self.username = username; self.password = password
        self.client = httpx.Client(base_url=self.base_url, verify=False, timeout=30.0)
        self.session_cookie = None
    def login(self):
        if self.session_cookie: return True
        try:
            r = self.client.post("/login", data={"username": self.username, "password": self.password})
            r.raise_for_status()
            cookie = r.cookies.get("session") or r.cookies.get("3x-ui")
            if not cookie: raise Exception("Cookie Sesi tidak ditemukan")
            self.session_cookie = f"{'session' if 'session' in r.cookies else '3x-ui'}={cookie}"
            return True
        except Exception as e:
            print(f"Login 3x-ui gagal: {e}"); return False
    def _request(self, method, path, **kwargs):
        if not self.session_cookie:
            if not self.login(): raise Exception("Tidak dapat login ke 3x-ui panel.")
        headers = kwargs.pop("headers", {}); headers.setdefault("Accept", "application/json")
        if self.session_cookie: headers["Cookie"] = self.session_cookie
        try:
            r = self.client.request(method, path, headers=headers, **kwargs)
            r.raise_for_status()
            return r.json() if r.text else {"success": True}
        except httpx.HTTPStatusError as e:
            print(f"Error request ke 3x-ui: {e.response.status_code} - {e.response.text}"); raise
    def add_client(self, inbound_id, remark, protocol):
        client_uuid = str(uuid.uuid4())
        client = {}
        if protocol == 'trojan':
            client = {"password": client_uuid, "email": remark, "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True, "tgId": "", "subId": secrets.token_hex(8), "comment": "", "reset": 0}
        else:
            client = {"id": client_uuid, "email": remark, "enable": True, "totalGB": 0, "expiryTime": 0}
        res = self._request("POST", "/panel/inbound/addClient", data={"id": inbound_id, "settings": json.dumps({"clients": [client]})})
        if res.get("success"): return client
        raise Exception(res.get("msg", "Gagal menambah client di 3x-ui"))
    def delete_client(self, inbound_id, client_uuid):
        res = self._request("POST", f"/panel/inbound/{inbound_id}/delClient/{client_uuid}")
        if res.get("success"): return True
        raise Exception(res.get("msg", "Gagal menghapus client di 3x-ui"))
    def get_inbound(self, inbound_id):
        res = self._request("POST", "/panel/inbound/list")
        if not res.get("success"): raise Exception("Gagal mengambil daftar inbound")
        for ib in res.get("obj", []):
            if ib["id"] == inbound_id: return ib
        return None
api = ThreeXUIApi(THREE_XUI_PANEL_URL, THREE_XUI_USERNAME, THREE_XUI_PASSWORD)

# --- FUNGSI DATABASE ---
DATABASE = 'vpn_store.db'
def get_db():
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES); db.row_factory = sqlite3.Row
    return db
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def init_db():
    with app.app_context():
        db = get_db(); cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, full_name TEXT, birth_date TEXT, email TEXT, phone TEXT, address TEXT, balance REAL DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS configs (id INTEGER PRIMARY KEY, user_id INTEGER, remark TEXT, protocol TEXT, inbound_id INTEGER, uuid TEXT, link TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, status TEXT NOT NULL DEFAULT 'active', FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS transactions (order_id TEXT PRIMARY KEY, user_id INTEGER, amount INTEGER, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id))''')
        db.commit()
    print("Database telah diinisialisasi.")

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

# --- DECORATORS & HELPER (Tidak Berubah) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function
def _build_config_link(protocol, remark, uuid_val, inbound_id):
    try:
        inbound_data = api.get_inbound(inbound_id)
        if not inbound_data: return None
        stream_settings = json.loads(inbound_data.get('streamSettings', '{}'))
        port, network = inbound_data.get('port'), stream_settings.get('network')
        ws_settings = stream_settings.get('wsSettings', {})
        path, host = ws_settings.get('path', '/'), ws_settings.get('headers', {}).get('Host', SERVER_ADDRESS)
        if protocol == 'vmess': vmess_json = {"v": "2", "ps": remark, "add": SERVER_ADDRESS, "port": port, "id": uuid_val, "aid": 0, "net": network, "type": "none", "host": host, "path": path, "tls": "tls"}; return "vmess://" + base64.b64encode(json.dumps(vmess_json).encode()).decode()
        elif protocol == 'trojan': return f"trojan://{uuid_val}@{SERVER_ADDRESS}:{port}?sni={host}&type={network}&path={quote(path)}#{quote(remark)}"
    except Exception as e: print(f"Gagal membuat link config: {e}"); return None

# --- RUTE HALAMAN & API ---
@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')
@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html')
@app.route('/store')
@login_required
def store(): return render_template('store.html')
@app.route('/topup')
@login_required
def topup(): return render_template('topup.html')
@app.route('/subscription/<int:config_id>')
@login_required
def subscription(config_id):
    config_data = get_db().execute("SELECT * FROM configs WHERE id = ? AND user_id = ?", (config_id, session['user_id'])).fetchone()
    if not config_data: return redirect(url_for('dashboard'))
    return render_template('subscription.html', config={'remark': config_data['remark'], 'link': config_data['link'] or "Gagal memuat link."})

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json(); username, password = data.get('username'), data.get('password')
    if not username or not password: return jsonify({'status': 'error', 'message': 'Username dan password wajib diisi'}), 400
    hashed_password = hash_password(password); db = get_db()
    try:
        db.execute("INSERT INTO users (username, password, full_name, birth_date, email, phone, address, balance) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (username, hashed_password, data.get('full_name'), data.get('birth_date'), data.get('email'), data.get('phone'), data.get('address'), 0)); db.commit()
        return jsonify({'status': 'success', 'message': 'Pendaftaran berhasil!'})
    except sqlite3.IntegrityError: return jsonify({'status': 'error', 'message': 'Username sudah terdaftar'}), 409

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(); user = get_db().execute("SELECT * FROM users WHERE username = ? AND password = ?", (data.get('username'), hash_password(data.get('password')))).fetchone()
    if user: session['user_id'], session['username'], session['is_admin'] = user['id'], user['username'], False; return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Username atau password salah'}), 401

@app.route('/api/logout')
def logout(): session.clear(); return redirect(url_for('home'))

@app.route('/api/user_data')
@login_required
def user_data():
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    user_info = dict(user); user_info.pop('password', None)
    return jsonify({'status': 'success', 'data': user_info})

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json(); db = get_db()
    db.execute("UPDATE users SET full_name=?, email=?, phone=?, address=?, birth_date=?, username=? WHERE id=?", (data.get('full_name'), data.get('email'), data.get('phone'), data.get('address'), data.get('birth_date'), data.get('username'), session['user_id']))
    db.commit(); session['username'] = data.get('username')
    return jsonify({'status': 'success', 'message': 'Profil berhasil diperbarui!'})

@app.route('/api/create_config', methods=['POST'])
@login_required
def create_config():
    db = get_db(); user = db.execute("SELECT balance FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if user['balance'] < CONFIG_PRICE: return jsonify({'message': f'Saldo Anda tidak cukup. Diperlukan Rp {CONFIG_PRICE}.'}), 400
    data = request.get_json(); protocol, remark = data.get('protocol'), data.get('remark')
    inbound_id = INBOUND_IDS.get(protocol)
    try:
        new_client = api.add_client(inbound_id, remark, protocol)
        client_uuid = new_client.get('password') if protocol == 'trojan' else new_client.get('id')
        config_link = _build_config_link(protocol, remark, client_uuid, inbound_id)
        if not config_link: raise Exception("Gagal membuat link dari helper.")
        cursor = db.execute("INSERT INTO configs (user_id, remark, protocol, inbound_id, uuid, link) VALUES (?, ?, ?, ?, ?, ?)", (session['user_id'], remark, protocol, inbound_id, client_uuid, config_link))
        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (CONFIG_PRICE, session['user_id']))
        db.commit()
        return jsonify({'message': 'Config berhasil dibuat!', 'config_id': cursor.lastrowid})
    except Exception as e: db.rollback(); return jsonify({'message': f'Gagal membuat config di server: {e}'}), 500

@app.route('/api/active_configs')
@login_required
def active_configs():
    configs = get_db().execute("SELECT * FROM configs WHERE user_id = ? AND status = 'active' ORDER BY id DESC", (session['user_id'],)).fetchall()
    return jsonify([dict(config) for config in configs])

@app.route('/api/purchase_history')
@login_required
def purchase_history():
    configs = get_db().execute("SELECT * FROM configs WHERE user_id = ? ORDER BY id DESC", (session['user_id'],)).fetchall()
    return jsonify([dict(config) for config in configs])

@app.route('/api/delete_config/<int:config_id>', methods=['POST'])
@login_required
def delete_config(config_id):
    db = get_db(); config = db.execute("SELECT * FROM configs WHERE id = ? AND user_id = ?", (config_id, session['user_id'])).fetchone()
    if not config: return jsonify({'message': 'Config tidak ditemukan.'}), 404
    try:
        api.delete_client(config['inbound_id'], config['uuid'])
        db.execute("UPDATE configs SET status = 'deleted' WHERE id = ?", (config_id,))
        db.commit()
        return jsonify({'message': f"Config '{config['remark']}' berhasil dihapus."})
    except Exception as e: return jsonify({'message': f"Gagal menghapus config: {e}"}), 500

@app.route('/api/monthly_charges')
@login_required
def monthly_charges():
    db = get_db()
    result = db.execute("SELECT COUNT(*) as count FROM configs WHERE user_id = ? AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now', 'localtime')", (session['user_id'],)).fetchone()
    count = result['count'] if result else 0
    total_charges = count * CONFIG_PRICE
    return jsonify({'total_charges': total_charges})

@app.route('/api/create_transaction', methods=['POST'])
@login_required
def create_transaction():
    data = request.get_json()
    amount = data.get('amount')
    if not isinstance(amount, int) or amount < 10000:
        return jsonify({'message': 'Jumlah top up tidak valid.'}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    order_id = f"TOPUP-{user['id']}-{int(datetime.now().timestamp())}"
    db.execute("INSERT INTO transactions (order_id, user_id, amount, status) VALUES (?, ?, ?, ?)", (order_id, user['id'], amount, 'pending'))
    db.commit()
    transaction_details = {'order_id': order_id, 'gross_amount': amount}
    customer_details = {'first_name': user['full_name'] or user['username'], 'email': user['email'] or f"{user['username']}@example.com"}
    enabled_payments = ["gopay", "shopeepay", "qris"]
    transaction_params = {'transaction_details': transaction_details, 'customer_details': customer_details, 'enabled_payments': enabled_payments}
    try:
        snap_token = snap.create_transaction(transaction_params)['token']
        return jsonify({'token': snap_token})
    except Exception as e:
        print(f"ERROR DARI MIDTRANS: {e}") # Log error untuk debugging
        return jsonify({'message': f"Gagal membuat token pembayaran: {e}"}), 500

@app.route('/api/payment_notification', methods=['POST'])
def payment_notification():
    data = request.get_json()
    order_id = data.get('order_id')
    transaction_status = data.get('transaction_status')
    db = get_db()
    transaction = db.execute("SELECT * FROM transactions WHERE order_id = ?", (order_id,)).fetchone()
    if not transaction or transaction['status'] == 'success':
        return jsonify({'message': 'Transaksi tidak valid atau sudah diproses.'})
    if transaction_status == 'settlement':
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (transaction['amount'], transaction['user_id']))
        db.execute("UPDATE transactions SET status = 'success' WHERE order_id = ?", (order_id,))
        db.commit()
        print(f"BERHASIL: Saldo user {transaction['user_id']} ditambah {transaction['amount']}.")
    elif transaction_status in ['cancel', 'deny', 'expire']:
        db.execute("UPDATE transactions SET status = 'failed' WHERE order_id = ?", (order_id,))
        db.commit()
        print(f"GAGAL: Transaksi {order_id} gagal atau kedaluwarsa.")
    return jsonify({'message': 'Notifikasi diterima.'})

# --- RUTE DAN API ADMIN ---
@app.route('/admin')
@admin_required
def admin_dashboard(): return render_template('admin.html')
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USERNAME and request.form['password'] == ADMIN_PASSWORD:
            session['is_admin'], session['username'] = True, 'Admin'
            return redirect(url_for('admin_dashboard'))
        else:
            return "Username atau Password Admin Salah", 401
    return render_template('admin_login.html')

@app.route('/api/admin/users')
@admin_required
def get_all_users():
    users = get_db().execute("SELECT id, username, full_name, balance FROM users").fetchall()
    return jsonify([dict(user) for user in users])

@app.route('/api/admin/user/<int:user_id>')
@admin_required
def get_user_details(user_id):
    user = get_db().execute("SELECT id, username, full_name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(dict(user)) if user else ({}, 404)

@app.route('/api/admin/update_balance', methods=['POST'])
@admin_required
def update_balance():
    data = request.get_json()
    user_id, amount = data.get('user_id'), data.get('amount')
    db = get_db()
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    db.commit()
    new_balance = db.execute("SELECT balance FROM users WHERE id = ?", (user_id,)).fetchone()['balance']
    return jsonify({'message': 'Saldo berhasil diperbarui!', 'new_balance': new_balance})

@app.route('/api/admin/user/update', methods=['POST'])
@admin_required
def admin_update_user():
    data = request.get_json()
    user_id, new_password = data.get('id'), data.get('new_password')
    db = get_db()
    if new_password:
        db.execute("UPDATE users SET username = ?, full_name = ?, email = ?, password = ? WHERE id = ?", (data['username'], data['full_name'], data['email'], hash_password(new_password), user_id))
    else:
        db.execute("UPDATE users SET username = ?, full_name = ?, email = ? WHERE id = ?", (data['username'], data['full_name'], data['email'], user_id))
    db.commit()
    return jsonify({'message': f'Data pengguna {data["username"]} berhasil diperbarui.'})

@app.route('/api/admin/user/<int:user_id>/configs')
@admin_required
def get_user_configs_for_admin(user_id):
    configs = get_db().execute("SELECT * FROM configs WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
    return jsonify([dict(config) for config in configs])

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
