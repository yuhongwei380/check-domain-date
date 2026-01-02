import sqlite3
from flask import Flask, render_template, request, jsonify
import whois
from datetime import datetime

app = Flask(__name__)
DB_FILE = 'domains.db'

# --- 数据库处理函数 ---
def init_db():
    """初始化数据库，创建表"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        # 创建一个简单的表，只存 ID 和 域名
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')
        conn.commit()

def get_stored_domains():
    """获取所有已保存的域名"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM domains")
        return cursor.fetchall() # 返回 [(1, 'google.com'), ...]

def add_stored_domain(domain_name):
    """添加域名"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO domains (name) VALUES (?)", (domain_name,))
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        return False # 域名已存在

def delete_stored_domain(domain_id):
    """删除域名"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        conn.commit()

# --- WHOIS 查询逻辑 ---
def get_domain_info(domain_id, domain_name):
    try:
        w = whois.whois(domain_name)
        
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
            
        if not exp_date:
            return {"id": domain_id, "domain": domain_name, "error": "未找到过期时间"}

        now = datetime.now()
        days_left = (exp_date - now).days
        
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
            "registrar": w.registrar,
            "status": status,
            "error": None
        }
    except Exception as e:
        return {"id": domain_id, "domain": domain_name, "error": str(e)}

# --- 路由 ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/domains', methods=['GET'])
def get_domains():
    """获取所有域名的状态"""
    stored_domains = get_stored_domains()
    results = []
    
    # 对数据库中的每个域名进行 Whois 查询
    # 注意：如果域名很多，这里会比较慢，生产环境建议使用后台任务或缓存
    for d_id, d_name in stored_domains:
        info = get_domain_info(d_id, d_name)
        results.append(info)
        
    return jsonify(results)

@app.route('/api/domains', methods=['POST'])
def add_domain():
    """添加新域名"""
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"success": False, "message": "域名不能为空"}), 400
    
    # 简单的域名清洗
    domain = domain.lower().replace('http://', '').replace('https://', '').split('/')[0]

    if add_stored_domain(domain):
        return jsonify({"success": True, "message": "添加成功"})
    else:
        return jsonify({"success": False, "message": "域名已存在"}), 400

@app.route('/api/domains/<int:domain_id>', methods=['DELETE'])
def delete_domain(domain_id):
    """删除域名"""
    delete_stored_domain(domain_id)
    return jsonify({"success": True})

if __name__ == '__main__':
    init_db() # 启动前初始化数据库
    print("数据库已初始化，服务启动中...")
    app.run(debug=True, port=5000)
