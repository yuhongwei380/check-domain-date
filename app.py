from flask import Flask, render_template, jsonify
import whois
from datetime import datetime

app = Flask(__name__)

# List of domains you want to monitor
MONITORED_DOMAINS = [
    "google.com",
    "example.com",
    "stackoverflow.com",
    "github.com",
    "openai.com"
]

def get_domain_info(domain_name):
    try:
        w = whois.whois(domain_name)
        
        # WHOIS data can be messy. Expiration date might be a list or a single object.
        exp_date = w.expiration_date
        
        if isinstance(exp_date, list):
            # If multiple dates, usually the first one is the registry expiration
            exp_date = exp_date[0]
            
        if not exp_date:
            return {"domain": domain_name, "error": "No expiration date found"}

        # Calculate days remaining
        now = datetime.now()
        days_left = (exp_date - now).days
        
        # Determine status
        if days_left < 30:
            status = "critical" # Red
        elif days_left < 90:
            status = "warning"  # Orange
        else:
            status = "good"     # Green

        return {
            "domain": domain_name,
            "expiration_date": exp_date.strftime('%Y-%m-%d'),
            "days_left": days_left,
            "registrar": w.registrar,
            "status": status,
            "error": None
        }

    except Exception as e:
        return {"domain": domain_name, "error": str(e)}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/status')
def status():
    results = []
    for domain in MONITORED_DOMAINS:
        info = get_domain_info(domain)
        results.append(info)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
