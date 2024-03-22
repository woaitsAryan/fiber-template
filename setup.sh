#!/bin/bash

JWT_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 32)

echo "Enter the new project name:"
read project_name

cp .env.sample .env

# Recursively find and replace "fiber-template-go" with the project name
grep -rl 'fiber-template-go' . | xargs sed -i "s/fiber-template-go/$project_name/g"

sed -i "s/JWT_KEY=.*$/JWT_KEY=$JWT_KEY/" .env
sed -i "s/DB_PASSWORD=.*$/DB_PASSWORD=$DB_PASSWORD/" .env
sed -i "s/REDIS_PASSWORD=.*$/REDIS_PASSWORD=$REDIS_PASSWORD/" .env

mkdir logs
touch logs/error.log
touch logs/info.log
touch logs/warn.log
touch logs/fatal.log
touch logs/panic.log
touch logs/debug.log

