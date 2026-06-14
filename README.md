# SecureCheck — AI Security Report Tool

Scan any website or IP with Nmap, run the results through GPT-4o, and deliver a plain-English PDF report a small business owner can actually understand.

**Business model:** Charge $50–$200 per report or $299/mo for monthly monitoring.

---

## What it does

1. User enters a domain or IP on the landing page
2. Server runs `nmap` against it (quick / standard / full scan depth)
3. Open ports are mapped to risk categories (HIGH/MEDIUM/LOW)
4. GPT-4o writes a human-readable report explaining each risk in plain English
5. `reportlab` renders a professional dark-themed PDF
6. User views the report online and/or downloads the PDF

---

## Local dev setup

```bash
# 1. Install nmap
sudo apt install nmap          # Ubuntu/Debian
brew install nmap              # macOS

# 2. Python dependencies
pip install -r requirements.txt

# 3. Set your OpenAI key
export OPENAI_API_KEY="sk-..."

# 4. Run
python app.py
# → http://localhost:5000
```

---

## Deploy to AWS (EC2)

### Step 1 — Launch EC2 instance

- **AMI:** Ubuntu 22.04 LTS
- **Type:** t3.small (enough for moderate traffic; scale up for Full scans)
- **Security Group inbound:**
  - Port 80  (HTTP — Nginx)
  - Port 443 (HTTPS — Nginx + Certbot)
  - Port 22  (SSH — your IP only)
- **Storage:** 20 GB gp3

### Step 2 — Install dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv nmap nginx certbot python3-certbot-nginx

# Create app directory
sudo mkdir -p /opt/securecheck
sudo chown ubuntu:ubuntu /opt/securecheck
cd /opt/securecheck

# Upload your code (from local machine):
# rsync -avz ./security_report_tool/ ubuntu@YOUR_IP:/opt/securecheck/

# Create venv and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt gunicorn
```

### Step 3 — Environment variables

```bash
sudo nano /etc/environment
# Add:
OPENAI_API_KEY=sk-your-key-here
SECRET_KEY=change-this-to-a-random-string
FLASK_ENV=production
```

Then reload: `source /etc/environment`

### Step 4 — Systemd service

```bash
sudo nano /etc/systemd/system/securecheck.service
```

```ini
[Unit]
Description=SecureCheck Flask App
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/securecheck
Environment="OPENAI_API_KEY=sk-your-key-here"
Environment="SECRET_KEY=change-this-to-a-random-string"
ExecStart=/opt/securecheck/venv/bin/gunicorn \
    --workers 2 \
    --bind 127.0.0.1:5000 \
    --timeout 300 \
    --access-logfile /var/log/securecheck/access.log \
    --error-logfile /var/log/securecheck/error.log \
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /var/log/securecheck
sudo chown ubuntu:ubuntu /var/log/securecheck
sudo systemctl daemon-reload
sudo systemctl enable securecheck
sudo systemctl start securecheck
```

### Step 5 — Nginx reverse proxy

```bash
sudo nano /etc/nginx/sites-available/securecheck
```

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        client_max_body_size 1M;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/securecheck /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Step 6 — HTTPS with Let's Encrypt

```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
# Follow prompts — auto-renews via cron
```

### Step 7 — (Optional) Stripe payments

To charge per report, add Stripe before returning the PDF:

```python
# In app.py, in the /report/<job_id> route, before render_template:
import stripe
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")

# Redirect to Stripe Checkout, store job_id in metadata
# On /stripe/webhook success → mark job as "paid" and allow PDF download
```

Set `STRIPE_SECRET_KEY` and `STRIPE_PRICE_ID` environment variables.

---

## Production checklist

- [ ] nmap installed on server
- [ ] OPENAI_API_KEY set (keep secret — never commit to git)
- [ ] SECRET_KEY set to a long random string
- [ ] HTTPS enabled via Certbot
- [ ] Systemd service running (`systemctl status securecheck`)
- [ ] Nginx configured with long proxy_read_timeout (nmap scans are slow)
- [ ] Rate limiting added to `/scan` endpoint (prevents abuse)
- [ ] Consider Redis + Celery to replace in-memory job store for multi-worker deploys
- [ ] Add payment gate (Stripe) before PDF download for monetization

---

## Rate limiting (important for production)

Add `flask-limiter` to cap scan requests:

```bash
pip install flask-limiter
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/scan", methods=["POST"])
@limiter.limit("5 per hour")
def start_scan():
    ...
```

---

## File structure

```
security_report_tool/
├── app.py              # Flask server (routes, job store, background threads)
├── scanner.py          # Nmap wrapper + port risk mapping
├── ai_reporter.py      # GPT-4o report generation
├── pdf_generator.py    # reportlab PDF builder
├── requirements.txt
├── README.md
└── templates/
    ├── index.html      # Landing page with scan form + live progress
    └── report.html     # Online report viewer
```

---

## Cost per report

| Item | Cost |
|------|------|
| GPT-4o (~2K tokens in + 2K out) | ~$0.03 |
| EC2 t3.small (shared) | ~$0.02 |
| **Total cost** | **~$0.05** |

At $50/report → **~1000x margin**. At $200/report → even better.
