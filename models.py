from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from db import engine

Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuario'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True)
    password = Column(String(200))
    rol = Column(String(20), default='usuario')  # Nuevo campo

class Ventas(Base):
    __tablename__ = 'ventas'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username_id = Column(Integer, ForeignKey('usuario.id'))
    venta = Column(Integer)
    
    # Relación
    usuario = relationship("Usuario")

Base.metadata.create_all(engine)