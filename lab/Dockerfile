FROM python:3.13-slim
WORKDIR /app
COPY lab/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY lab /app/lab
COPY core/__init__.py core/lab_policy.py core/template_catalog.py /app/core/
EXPOSE 8000
CMD ["uvicorn", "lab.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
