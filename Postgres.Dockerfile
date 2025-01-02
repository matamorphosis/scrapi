FROM postgres:latest

COPY scrapi_schema.sql /docker-entrypoint-initdb.d/