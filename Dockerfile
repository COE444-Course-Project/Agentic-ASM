# Containerizes the attacker agent (CLI + GUI). Ollama is deliberately NOT
# containerized here -- Docker Desktop on macOS has no GPU/Metal passthrough,
# so an in-container Ollama would be far slower than a native install, and
# the team's machines are mixed hardware. Install Ollama natively on the
# host and this image reaches it via OLLAMA_BASE_URL=http://host.docker.internal:11434
# (wired up in docker-compose.yml).
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8765

# Default to the live dashboard, reachable at http://localhost:8765 once
# docker-compose.yml publishes this port. Run the CLI instead with:
#   docker compose run agent python3 run_attacker.py --target http://vampi-vulnerable:5000
CMD ["python3", "gui/server.py", "--host", "0.0.0.0", "--port", "8765"]
