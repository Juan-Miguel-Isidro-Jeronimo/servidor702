from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Example: Replace with your actual database URL
DATABASE_URL = "postgresql+psycopg2://postgres:0704@localhost:5432/bd702"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Session=SessionLocal()
Base = declarative_base()