#!/bin/bash
set -e

mkdir -p staticfiles media logs

# PostgreSql
if [ -n "$POSTGRES_HOST" ]; then
    export PGPASSWORD=$POSTGRES_PASSWORD
    until pg_isready -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER; do
        sleep 2
    done
    echo "PostgreSQL ready at $POSTGRES_HOST:$POSTGRES_PORT"
else
    echo "Using SQLite database"
fi

# RabbitMQ
if [[ "$CELERY_BROKER_URL" == amqp* ]]; then
    echo "Waiting for RabbitMQ..."
    RABBIT_HOST=$(echo $CELERY_BROKER_URL | sed -r 's/^amqp:\/\/[^:]*:[^@]*@([^:]+):?[0-9]*\/\/$/\1/')
    RABBIT_HOST=${RABBIT_HOST:-rabbitmq}
    
    until nc -z $RABBIT_HOST 5672; do
        echo "RabbitMQ is unavailable - sleeping"
        sleep 2
    done
    echo "RabbitMQ ready at $RABBIT_HOST:5672"
fi

python manage.py makemigrations
python manage.py migrate

python manage.py collectstatic --noinput

if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] ; then
    python manage.py createsuperuser --noinput --username $DJANGO_SUPERUSER_USERNAME --email $DJANGO_SUPERUSER_EMAIL || true
fi

if [ "$1" = "web" ]; then
    echo "Starting web server..."
    exec python manage.py runserver 0.0.0.0:8000
elif [ "$1" = "celery" ]; then
    echo "Starting Celery worker..."
    exec celery -A IDS worker -l info --pool=prefork --concurrency=4 --without-heartbeat --without-gossip
elif [ "$1" = "beat" ]; then
    echo "Starting Celery beat..."
    exec celery -A IDS beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
else
    echo "Unknown service: $1"
    exit 1
fi 