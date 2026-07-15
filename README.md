# Guardrail AI

An AI security and guardrail management system built with FastAPI, React, and Docker.

## 🚀 Features

- **Backend API**: FastAPI-based REST API with async support
- **Frontend**: React + Vite application for guardrail management
- **Database**: PostgreSQL for persistent storage
- **Graph Database**: Neo4j for attack path modeling
- **Cache**: Redis for caching and task queue backend
- **Task Queue**: Celery + RabbitMQ for background processing
- **Monitoring**: Prometheus + Grafana for comprehensive monitoring
- **Logging**: Structured logging with health checks
- **Security**: Built-in authentication and authorization

## 🏗️ Architecture

The system consists of the following main components:

- **API Service**: Main FastAPI application handling HTTP requests
- **Celery Workers**: Background task processors for guardrail evaluations
- **Celery Beat**: Scheduler for periodic maintenance tasks
- **Frontend**: React-based user interface
- **PostgreSQL**: Primary database
- **Neo4j**: Graph database for complex relationships
- **Redis**: Caching and task results storage
- **RabbitMQ**: Message broker for Celery
- **Prometheus**: Metrics collection
- **Grafana**: Monitoring dashboards

## 📋 Prerequisites

- Docker and Docker Compose
- Docker Compose V2 (recommended)

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Guardrail-AI
   ```

2. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Build and start the services**:
   ```bash
   docker-compose up -d
   ```

4. **Check service status**:
   ```bash
   docker-compose ps
   ```

## 🌐 Access Points

Once running, the following services will be available:

- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Grafana**: http://localhost:3002 (admin/admin)
- **Prometheus**: http://localhost:9091
- **RabbitMQ Management**: http://localhost:15672
- **Neo4j Browser**: http://localhost:7474

## 🔑 Default Credentials

Update these in your `.env` file for production:

- **Grafana**: admin / your-secure-grafana-password
- **RabbitMQ**: guardrail_user / your-secure-rabbitmq-password
- **PostgreSQL**: guardrail_user / your-secure-postgres-password
- **Neo4j**: neo4j / your-secure-neo4j-password

## 🛠️ Development

### Backend Development

```bash
# Activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

### Database Migrations

```bash
# Generate migration
alembic revision --autogenerate -m "description"

# Apply migration
alembic upgrade head
```

## 🧪 Testing

```bash
# Run backend tests
pytest

# Run with coverage
pytest --cov=app
```

## 📊 Monitoring

The system includes comprehensive monitoring:

- **Prometheus**: Collects metrics from all services
- **Grafana**: Pre-configured dashboards for visualization
- **Health Checks**: `/health` endpoint for service health
- **Exporters**: PostgreSQL, Redis, and system metrics

## 🔒 Security

Before deploying to production:

1. Change all default passwords in `.env`
2. Generate a strong `SECRET_KEY`
3. Configure SSL/TLS certificates
4. Set up proper firewall rules
5. Enable authentication for all services
6. Review and update CORS settings
7. Configure rate limiting
8. Set up log aggregation

## 🐳 Docker Commands

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f api

# Restart specific service
docker-compose restart api

# Remove volumes (WARNING: deletes data)
docker-compose down -v
```

## 📝 API Documentation

Interactive API documentation is available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Troubleshooting

### Services won't start

Check if ports are already in use:
```bash
netstat -tulpn | grep -E ':(3000|8000|5432|6379|5672)'
```

### Database connection issues

Ensure PostgreSQL is healthy:
```bash
docker-compose logs postgres
```

### High memory usage

Reduce container limits in `docker-compose.yml` or use the optimized Dockerfile:
```yaml
api:
  build:
    dockerfile: docker/app.Dockerfile.optimized
```

## 📞 Support

For issues and questions, please open an issue on the repository.
