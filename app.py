import sqlite3
from flask import Flask, render_template, request, jsonify
import subprocess
import re
from datetime import datetime, timezone  # ✅ 正确导入

app = Flask(__name__)
DB_FILE = 'domains.db'


# --- 数据库处理 ---
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


# --- 解析 WHOIS 输出中的过期时间 ---
def parse_expiry_from_whois_output(output):
    lines = output.split('\n')
    expiry_keywords = [
        'expire', 'expiration', 'registry exp', 'paid-till',
        '过期时间', '过期日期', 'expiry date', 'renewal date'
    ]
    date_patterns = [
        r'\d{4}-\d{2}-\d{2}',          # 2025-08-14
        r'\d{2}-\d{2}-\d{4}',          # 14-08-2025
        r'\d{2}/\d{2}/\d{4}',          # 08/14/2025
        r'\d{4}\.\d{2}\.\d{2}',        # 2025.08.14
    ]
    
    for line in lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in expiry_keywords):
            for pattern in date_patterns:
                match = re.search(pattern, line)
                if match:
                    date_str = match.group()
                    if re.match(r'\d{4}-\d{2}-\d{2}', date_str):
                        return date_str
                    elif re.match(r'\d{2}-\d{2}-\d{4}', date_str):
                        parts = date_str.split('-')
                        return f"{parts[2]}-{parts[0]}-{parts[1]}"
                    elif re.match(r'\d{2}/\d{2}/\d{4}', date_str):
                        parts = date_str.split('/')
                        return f"{parts[2]}-{parts[0]}-{parts[1]}"
                    elif re.match(r'\d{4}\.\d{2}\.\d{2}', date_str):
                        return date_str.replace('.', '-')
    return None


# --- 查询域名信息 ---
def get_domain_info(domain_id, domain_name):
    try:
        result = subprocess.run(
            ['whois', domain_name],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or "WHOIS 命令执行失败"
            return {
                "id": domain_id,
                "domain": domain_name,
                "error": f"执行错误: {error_msg}",
                "status": "error"
            }

        expiry_date_str = parse_expiry_from_whois_output(result.stdout)
        if not expiry_date_str:
            return {
                "id": domain_id,
                "domain": domain_name,
                "error": "未在 WHOIS 中找到过期时间（可能域名未注册或格式不支持）",
                "status": "unknown"
            }

        try:
            exp_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
        except ValueError:
            return {
                "id": domain_id,
                "domain": domain_name,
                "error": f"无法解析日期格式: {expiry_date_str}",
                "status": "error"
            }

        # ✅ 使用 timezone.utc（小写）—— 兼容所有 Python 3.6+
        now = datetime.now(timezone.utc)
        days_left = (exp_date.date() - now.date()).days

        if days_left < 0:
            status = "expired"
        elif days_left < 30:
            status = "critical"
        elif days_left < 90:
            status = "warning"
        else:
            status = "good"

        return {
            "id": domain_id,
            "domain": domain_name,
            "expiration_date": expiry_date_str,
            "days_left": days_left,
            "registrar": "（未解析注册商）",
            "status": status,
            "error": None
        }

    except subprocess.TimeoutExpired:
        return {
            "id": domain_id,
            "domain": domain_name,
            "error": "WHOIS 查询超时（网络或服务器无响应）",
            "status": "timeout"
        }
    except FileNotFoundError:
        return {
            "id": domain_id,
            "domain": domain_name,
            "error": "系统缺少 'whois' 命令，请运行: sudo apt install whois",
            "status": "error"
        }
    except Exception as e:
        return {
            "id": domain_id,
            "domain": domain_name,
            "error": f"未知错误: {str(e)}",
            "status": "error"
        }


# --- Flask 路由 ---
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

    if not domain or '.' not in domain:
        return jsonify({"success": False, "message": "无效域名格式"}), 400

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
    print("✅ 域名到期监控服务启动（使用系统 WHOIS）")
    print("💡 请确保已安装 'whois'：sudo apt install whois")
    app.run(debug=True, port=5000, host='0.0.0.0')
