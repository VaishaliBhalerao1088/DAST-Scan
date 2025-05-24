# StackGuardian

StackGuardian is a web-based security scanning platform designed to help developers and security teams identify and mitigate vulnerabilities in their applications, APIs, Kubernetes deployments, and cloud configurations. It provides a unified interface to orchestrate various open-source security tools and manage the lifecycle of vulnerabilities.

## Features

*   **User Management:** Secure registration and login using JWT. Role-based access control (planned).
*   **Passive Scanning:**
    *   SSL/TLS certificate analysis.
    *   HTTP header security checks.
*   **Active Scanning:**
    *   Integration with OWASP ZAP for dynamic application security testing (DAST).
    *   Integration with Nuclei for template-based vulnerability scanning.
*   **Task Management:** Asynchronous task execution using Celery and Redis for long-running scans.
*   **Reporting:** (Basic) API endpoints to fetch scan summaries and vulnerability lists.
*   **CI/CD Integration:** API endpoints to trigger scans and fetch results, suitable for integration into CI/CD pipelines.
*   **(Planned Features):** UI dashboard, Kubernetes scanning, cloud configuration scanning, advanced reporting, vulnerability management workflows.

## Tech Stack

*   **Backend:** FastAPI (Python)
*   **Task Queue:** Celery with Redis
*   **Database:** SQLAlchemy with PostgreSQL (currently using SQLite for development)
*   **Authentication:** JWT (python-jose, passlib)
*   **Scanning Tools:** OWASP ZAP, Nuclei
*   **(Planned Frontend):** React

## Prerequisites

Before you begin, ensure you have the following installed:

*   **Python 3.8+**
*   **pip** (Python package installer)
*   **Redis Server:** For Celery message broker and results backend.
*   **PostgreSQL Server:** Recommended for production. The application currently uses SQLite for development if the `DATABASE_URL` environment variable is not changed.
*   **OWASP ZAP:** Required for active ZAP scans. Can be installed locally or run via Docker. The `zap-baseline.py` script (usually bundled with ZAP) is used by the tasks. See [Tool Setup Guide](./docs/tool_setup.md).
*   **Nuclei:** Required for active Nuclei scans. Installable binary. See [Tool Setup Guide](./docs/tool_setup.md).

## Project Structure

- `stackguardian/`: Root directory.
  - `stackguardian/`: Main application directory.
    - `api/`: FastAPI routers.
    - `models/`: Pydantic schemas and SQLAlchemy models.
    - `services/`: Business logic.
    - `tasks/`: Celery tasks.
    - `core/`: Core components (database, config).
    - `utils/`: Utility functions (if any).
    - `main.py`: FastAPI app initialization.
  - `docs/`: Documentation files.
  - `requirements.txt`: Project dependencies.
  - `.gitignore`: Git ignore file.
  - `README.md`: This file.

## Setup and Running the Backend

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd stackguardian
    ```

2.  **Install Python Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Environment Variables:**
    Create a `.env` file in the `stackguardian` root directory or set environment variables manually. Critical variables include:
    *   `DATABASE_URL`: SQLAlchemy database connection string (e.g., `postgresql://user:pass@host:port/dbname` or `sqlite:///./stackguardian.db` for SQLite).
    *   `SECRET_KEY`: A strong secret key for JWT and other security functions. Generate one using `openssl rand -hex 32`.
    *   `CELERY_BROKER_URL`: Celery broker URL (e.g., `redis://localhost:6379/0`).
    *   `CELERY_RESULT_BACKEND`: Celery result backend URL (e.g., `redis://localhost:6379/0`).
    *   `ZAP_BASE_URL`: Base URL for the ZAP API (e.g., `http://localhost:8080`).
    *   `ZAP_API_KEY`: Your ZAP API key (optional, depending on your ZAP configuration).

    Example `.env` content:
    ```env
    DATABASE_URL="sqlite:///./stackguardian.db"
    SECRET_KEY="your_generated_secret_key"
    CELERY_BROKER_URL="redis://localhost:6379/0"
    CELERY_RESULT_BACKEND="redis://localhost:6379/0"
    ZAP_BASE_URL="http://localhost:8080"
    # ZAP_API_KEY="your_zap_api_key"
    ```
    *Note: The application currently loads configuration from `stackguardian.stackguardian.core.config.py` which reads environment variables directly. Support for loading from a `.env` file using a library like `python-dotenv` can be added to `config.py` if desired.*

4.  **Database Setup:**
    The application uses SQLAlchemy and will attempt to create all defined database tables automatically on its first run based on the models. For production environments, it's highly recommended to use a database migration tool like Alembic. (Alembic setup is not yet part of this project).

5.  **Run the FastAPI Application:**
    ```bash
    uvicorn stackguardian.stackguardian.main:app --reload
    ```
    The application will typically be available at `http://localhost:8000`.

6.  **Run the Celery Worker:**
    Ensure your Redis server is running. In a separate terminal, start the Celery worker:
    ```bash
    celery -A stackguardian.stackguardian.tasks.celery_worker worker -l info -P solo
    ```
    *Note: The `-P solo` option is recommended for SQLite to avoid concurrency issues. It can be removed if you are using PostgreSQL or another database that handles concurrency well.*

## API Access

*   **Auto-generated Documentation:** FastAPI provides automatic API documentation. When the application is running, you can access:
    *   Swagger UI: [`http://localhost:8000/docs`](http://localhost:8000/docs)
    *   ReDoc: [`http://localhost:8000/redoc`](http://localhost:8000/redoc)
*   **Authentication:** Most API endpoints are protected. Obtain a JWT token by sending user credentials to `/api/v1/users/login`. Include this token in the `Authorization: Bearer <token>` header for subsequent requests.

## Available API Modules

*   **User Management (`/api/v1/users`):** Handles user registration and login.
*   **Passive Scanning (`/api/v1/passive`):** Endpoints for SSL/TLS checks and HTTP header analysis.
*   **Active Scanning (`/api/v1/active`):** Endpoints to initiate scans with OWASP ZAP and Nuclei.
*   **Reporting (`/api/v1/reports`):** Endpoints to fetch scan summaries and vulnerability lists.
*   **CI/CD Integration (`/api/v1/cicd`):** Endpoints designed for triggering scans and fetching results within CI/CD pipelines.

## Tool Setup

For active scanning capabilities, specific tools like OWASP ZAP and Nuclei need to be set up correctly.
Refer to the [Tool Setup Guide](./docs/tool_setup.md) for detailed installation and configuration instructions.

## Contributing

Please read `CONTRIBUTING.md` (to be created) for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the `LICENSE.md` file (to be created) for details.
