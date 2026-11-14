import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import get_settings

settings = get_settings()

engine = create_engine(
    # Test/build environments do not need a running MySQL driver just to
    # import the application models. Production never sets this variable and
    # continues to use the configured MySQL URL.
    os.environ.get("VPN_PANEL_TEST_DATABASE_URL") or settings.SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=280,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
