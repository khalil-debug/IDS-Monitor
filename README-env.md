# IDS Environment Configuration

This project supports two deployment modes, each with its own environment configuration file:

## 1. Docker Deployment (`.env.docker`)

Full deployment using Docker Compose with separate containers for:
- Django web application
- PostgreSQL database
- RabbitMQ message broker
- Celery workers and beat scheduler

**To use this configuration:**

1. Rename `.env.docker` to `.env` or load it explicitly:
   ```
   cp .env.docker .env
   ```

2. Start the Docker containers:
   ```
   docker-compose up -d
   ```

3. Access the application at http://localhost:8000

## 2. Endpoint Mode (`.env.endpoint`)

Lightweight standalone deployment without external dependencies:
- Uses SQLite instead of PostgreSQL
- Runs without RabbitMQ or Redis
- Processes tasks synchronously
- Stores notifications locally when offline

**To use this configuration:**

1. Rename `.env.endpoint` to `.env` or load it explicitly:
   ```
   cp .env.endpoint .env
   ```

2. Set up the endpoint:
   ```
   python manage.py setup_endpoint
   ```

3. Run the endpoint:
   ```
   python manage.py run_endpoint
   ```

4. Access the application at http://localhost:8000

## Configuration Details

### Docker Mode Settings

- `USE_SQLITE=false`: Uses PostgreSQL
- `USE_RABBITMQ=true`: Enables RabbitMQ for task queue
- `ENDPOINT_MODE=false`: Disables endpoint mode features
- `CELERY_TASK_ALWAYS_EAGER=false`: Processes tasks asynchronously

### Endpoint Mode Settings

- `USE_SQLITE=true`: Uses SQLite database
- `USE_RABBITMQ=false`: Disables external message brokers
- `ENDPOINT_MODE=true`: Enables endpoint mode features
- `USE_DB_AS_BROKER=true`: Uses database as message broker
- `CELERY_TASK_ALWAYS_EAGER=true`: Processes tasks synchronously
- `USE_LOCAL_FALLBACK=true`: Enables local storage for offline operation
- `CELERY_FALLBACK_TO_DISK=true`: Allows disk-based task persistence

## Switching Between Modes

To switch between deployment modes, copy the appropriate environment file:

```bash
# For Docker mode
cp .env.docker .env

# For Endpoint mode
cp .env.endpoint .env
```

Then restart the application with the appropriate command for that mode. 