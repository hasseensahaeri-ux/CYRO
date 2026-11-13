# CYRO production server settings.
# The dashboard keeps an SSE connection open; sync workers time out on it.
worker_class = "gthread"
workers = 1
threads = 12
timeout = 120
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 50
