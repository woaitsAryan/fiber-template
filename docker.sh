#!/bin/bash

set -a
source .env
set +a

echo "Enter the container name:"
read project_name

# Run PostgreSQL container
docker run --name postgres-$project_name -e POSTGRES_DB=$DB_NAME -e POSTGRES_USER=$DB_USER -e POSTGRES_PASSWORD=$DB_PASSWORD -p $DB_PORT:5432 -v ./init.sql:/docker-entrypoint-initdb.d/init.sql -d postgres

# Run Redis container
docker run --name redis-$project_name -e REDIS_PASSWORD=$REDIS_PASSWORD -p $REDIS_PORT:6379 -d redis redis-server --requirepass $REDIS_PASSWORD