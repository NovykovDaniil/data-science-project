FROM python:3.11

WORKDIR /code

COPY . .

RUN pip install --no-cache-dir poetry \
    && poetry install --no-dev

EXPOSE 8080
RUN chmod +x run.sh
CMD ["./run.sh"]
