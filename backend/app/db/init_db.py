import logging
from app.db.session import engine, Base
import app.db.models  # ensure models are registered

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db():
    """Create all database tables on application startup."""
    try:
        logger.info("Initializing database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise


if __name__ == "__main__":
    init_db()
