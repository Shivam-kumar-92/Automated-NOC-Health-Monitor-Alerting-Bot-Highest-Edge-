FROM python:3.12-alpine

# Install iputils so Linux `ping -c -W` matches standard Linux behavior
RUN apk add --no-cache iputils

WORKDIR /app
COPY . /app

RUN mkdir -p /app/data /app/logs

EXPOSE 8080

ENTRYPOINT ["python3", "monitor.py", "--config", "config.json", "--dashboard", "--dashboard-host", "0.0.0.0", "--dashboard-port", "8080"]
