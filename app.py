import sqlite3
from flask import Flask, render_template, request, jsonify
import requests
from datetime import datetime
import dateutil.parser # 这是一个强大的时间解析库，通常随 requests 或其他库安装，如果没有请 pip install python-dateutil

app = Flask(__name__)
DB_FILE = 'domains.db'

# --- 数据库处理 (保持不变) ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')
        conn.commit()

def get_stored_domains():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM domains")
        return cursor.fetchall()

def add_stored_domain(domain_name):
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO domains (name) VALUES (?)", (domain_name,))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False

def delete_stored_domain(domain_id):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        conn.commit()

# --- 新的核心逻辑：使用 RDAP (HTTP) 替代 Whois (Port 43) ---
def get_domain_info(domain_id, domain_name):
    rdap_url = f"https://rdap.org/domain/{domain_name}"
    
    try:
        # 使用 HTTP 请求，防火墙通常不会拦截 HTTPS
        response = requests.get(rdap_url, timeout=10)
        
        if response.status_code == 404:
            return {"id": domain_id, "domain": domain_name, "error": "域名未注册或找不到"}
        
        if response.status_code != 200:
            return {"id": domain_id, "domain": domain_name, "error": f"查询失败 (HTTP {response.status_code})"}

        data = response.json()
        
        # 1. 解析过期时间
        expiration_date_str = None
        # RDAP 返回的是一个 events 列表，我们需要找到 'expiration' 事件
        events = data.get('events', [])
        for event in events:
            if event.get('eventAction') in ['expiration', 'registration expiration']:
                expiration_date_str = event.get('eventDate')
                break
        
        if not expiration_date_str:
            return {"id": domain_id, "domain": domain_name, "error": "未找到过期时间字段"}

        # 2. 解析时间字符串 (ISO 8601 格式)
        # 格式通常是 "2025-08-14T04:00:00Z"
        exp_date = dateutil.parser.parse(expiration_date_str)
        # 转为不带时区的本地时间用于计算天数 (简单处理)
        exp_date_naive = exp_date.replace(tzinfo=None)
        now = datetime.utcnow()
        
        days_left = (exp_date_naive - now).days
        
        # 3. 获取注册商名字
        registrar_name = "未知"
        entities = data.get('entities', [])
        for entity in entities:
            if 'registrar' in entity.get('roles', []):
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    # vCard 格式比较复杂，通常找 fn (Full Name)
                    for item in vcard[1]:
                        if item[0] == 'fn':
                            registrar_name = item[3]
                            break
                break

        # 4. 判定状态颜色
        if days_left < 30:
            status = "critical"
        elif days_left < 90:
            status = "warning"
        else:
            status = "good"

        return {
            "id": domain_id,
            "domain": domain_name,
            "expiration_date": exp_date.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "registrar": registrar_name,
            "status": status,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"id": domain_id, "domain": domain_name, "error": "连接超时 (请检查网络)"}
    except Exception as e:
        print(f"Error parsing {domain_name}: {str(e)}")
        return {"id": domain_id, "domain": domain_name, "error": "解析数据出错"}

# --- 路由 (保持不变) ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
def get_domains():
    stored_domains = get_stored_domains()
    results = []
    for d_id, d_name in stored_domains:
        info = get_domain_info(d_id, d_name)
        results.append(info)
    return jsonify(results)

@app.route('/api/domains', methods=['POST'])
def add_domain():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"success": False, "message": "域名不能为空"}), 400
    
    domain = domain.lower().strip().replace('http://', '').replace('https://', '').split('/')[0]

    if add_stored_domain(domain):
        return jsonify({"success": True, "message": "添加成功"})
    else:
        return jsonify({"success": False, "message": "域名已存在"}), 400

@app.route('/api/domains/<int:domain_id>', methods=['DELETE'])
def delete_domain(domain_id):
    delete_stored_domain(domain_id)
    return jsonify({"success": True})

if __name__ == '__main__':
    init_db()
    print("服务启动中 (RDAP模式)...")
    # 保持 0.0.0.0 以允许局域网访问
    app.run(debug=True, port=5000, host='0.0.0.0')
