# Combined-PR fixture: vulnerable Dockerfile alongside vulnerable Python
# code. Exercises iac_scan running in parallel with sast_scan + secrets_scan.
#
# Intended Checkov failures:
#   - CKV_DOCKER_3 — no USER directive (runs as root)
#   - CKV_DOCKER_7 — `:latest` tag

FROM python:latest

COPY app.py /app/app.py
WORKDIR /app
RUN pip install requests
CMD ["python", "app.py"]
