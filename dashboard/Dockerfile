FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir streamlit==1.28.2 pandas==2.1.4
COPY app/ ./app/

EXPOSE 8501
CMD ["streamlit", "run", "app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]
