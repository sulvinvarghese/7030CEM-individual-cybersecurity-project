FROM python:3.8-slim
WORKDIR /app
COPY generate_realtime_logs.py ./
RUN pip install pandas
CMD ["python", "generate_realtime_logs.py"]
