# Gunicorn configuration for Render deployment
bind = "0.0.0.0:10000"
workers = 2
threads = 4
timeout = 600          # 10 min — covers large DOCX/PDF streaming + async internal builds
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
preload_app = False    # Don't preload — avoids memory issues with forks
