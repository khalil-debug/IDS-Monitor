#!/bin/bash
set -e

wait_for_postgres() {
    echo "Waiting for postgres..."
    while ! nc -z db 5432; do
        sleep 1
        echo "Still waiting for postgres..."
    done
    echo "PostgreSQL started"
}

apply_migrations() {
    echo "Running database migrations..."
    python manage.py makemigrations
    python manage.py migrate
    
    if [ $? -eq 0 ]; then
        echo "Migrations completed successfully"
    else
        echo "Migration failed"
        exit 1
    fi
}

create_superuser() {
    echo "Creating superuser if it doesn't exist..."
    python manage.py shell -c "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@example.com', 'admin') if not User.objects.filter(username='admin').exists() else None"
}

# Main
wait_for_postgres
apply_migrations
create_superuser

python manage.py runserver 0.0.0.0:8000