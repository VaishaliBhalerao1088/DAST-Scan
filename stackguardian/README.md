# StackGuardian

StackGuardian is a FastAPI-based application for managing and automating cloud infrastructure.

## Project Structure

- `stackguardian/`: Root directory.
  - `stackguardian/`: Main application directory.
    - `api/`: FastAPI routers.
    - `models/`: Pydantic schemas and SQLAlchemy models.
    - `services/`: Business logic.
    - `tasks/`: Celery tasks.
    - `core/`: Core components (database, config).
    - `utils/`: Utility functions.
    - `main.py`: FastAPI app initialization.
  - `requirements.txt`: Project dependencies.
  - `.gitignore`: Git ignore file.
  - `README.md`: This file.

## Setup

1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Configure the application in `stackguardian/core/config.py`.
4. Set up the database using `stackguardian/core/database.py`.
5. Run the FastAPI application: `uvicorn stackguardian.main:app --reload`

### Running the Celery Worker

To process background tasks, start the Celery worker:

```bash
celery -A stackguardian.stackguardian.tasks.celery_worker worker -l info
```
Ensure your Redis server is running.

## Contributing

Please read `CONTRIBUTING.md` for details on our code of conduct, and the process for submitting pull requests to us.

## License

This project is licensed under the MIT License - see the `LICENSE.md` file for details.
