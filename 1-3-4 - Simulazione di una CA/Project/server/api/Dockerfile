# syntax=docker/dockerfile:1.4
FROM python:3.11

WORKDIR /app

COPY requirements.txt /app
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

COPY ./src /app

ENTRYPOINT ["python3"]
CMD ["app.py", "admin", "gBhx*Rob72u*u2J@NL82of9rm=9sGCjU"]