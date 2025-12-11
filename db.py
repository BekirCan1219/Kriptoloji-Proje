from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# SQL Server bağlantı adresin (senin verdiğin bilgilere göre)
DATABASE_URL = (
    "mssql+pyodbc://sa:12345@DESKTOP/kripto"
    "?driver=ODBC+Driver+17+for+SQL+Server"
)

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50))
    room = Column(String(50))
    algorithm = Column(String(20))
    plaintext = Column(Text)
    ciphertext = Column(Text)
    timestamp = Column(DateTime, default=datetime.now)

# Tabloları oluştur
Base.metadata.create_all(bind=engine)
