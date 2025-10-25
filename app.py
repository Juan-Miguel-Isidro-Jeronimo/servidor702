from flask import Flask, request, jsonify
import json
from db import Session, engine
from models import Usuario, Ventas
from flasgger import Swagger
from sqlalchemy import text
import jwt
import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from flask_cors import CORS

# Cargar variables de entorno
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))

app = Flask(__name__)
# Habilitar CORS para todas las rutas y orígenes (dev)
CORS(app, resources={r"/*": {"origins": "*"}})
# Configuración básica de Flasgger
app.config['SWAGGER'] = {
    'title': 'API Usuarios',
    'uiversion': 3
}
swagger = Swagger(app)

# Crear admin por defecto y utilidades de token
def crear_admin_por_defecto():
  from db import Session
  admin_username = os.getenv('ADMIN_USERNAME', 'admin')
  admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
  existe = Session.query(Usuario).filter_by(username=admin_username).first()
  if not existe:
    hash_pw = generate_password_hash(admin_password, method='pbkdf2:sha256')
    nuevo = Usuario(username=admin_username, password=hash_pw, rol='admin')
    Session.add(nuevo)
    try:
      Session.commit()
      print(f"Usuario admin '{admin_username}' creado por defecto")
    except Exception as e:
      Session.rollback()
      print('Error creando admin por defecto:', e)

def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None
    if 'Authorization' in request.headers:
      auth_header = request.headers['Authorization']
      parts = auth_header.split()
      if len(parts) == 2 and parts[0] == 'Bearer':
        token = parts[1]
    if not token:
      return jsonify({'message': 'Token is missing!'}), 401
    try:
      data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
      current_user = Session.query(Usuario).filter_by(id=data['id']).first()
      if not current_user:
        return jsonify({'message': 'Token is invalid (user not found)'}), 401
      request.current_user = current_user
    except jwt.ExpiredSignatureError:
      return jsonify({'message': 'Token has expired!'}), 401
    except Exception as e:
      return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
    return f(*args, **kwargs)
  return decorated

@app.route('/')
def home():
    return 'Hello, Flask!'


@app.route('/ping', methods=['GET'])
def ping():
  return jsonify({'message': 'pong'})

@app.route('/saludar', methods=['GET'])
def saludar():
    return jsonify({"message": "Hola, Mundo!"})

@app.route('/operar', methods=['POST'])
def operar():
    try:
        datos = json.loads(request.data)
        datos1 = float(datos.get('1', 0))
        datos2 = float(datos.get('2', 0))

        resultado = {
            'suma': datos1 + datos2,
            'resta': datos1 - datos2,
            'multiplicacion': datos1 * datos2,
            'division': 'Error: división por cero' if datos2 == 0 else datos1 / datos2
        }

        return jsonify(resultado)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/crear_usuario', methods=['POST'])
def crear_usuario():
    """
    Crea un nuevo usuario.
    ---
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
    responses:
      201:
        description: Usuario creado correctamente
      500:
        description: Error al crear el usuario
    """
    datos = request.form
    username = datos.get('username', 'LEO')
    password = datos.get('password', '20')
    # Encriptar la contraseña antes de guardarla
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    nuevo_usuario = Usuario(username=username, password=password_hash)
    Session.add(nuevo_usuario)
    try:
        Session.commit()
        return jsonify({"message": "Usuario creado correctamente"}), 201
    except:
        Session.rollback()
        return jsonify({"error": "Error al crear el usuario"}), 500

@app.route('/obtener_usuario', methods=['GET'])
def obtener_usuario():
    """
    Obtiene el primer usuario.
    ---
    responses:
      200:
        description: Usuario encontrado
      404:
        description: No se encontró ningún usuario
      500:
        description: Error al obtener el usuario
    """
    try:
        usuarios = Session.query(Usuario).all()
        if usuarios:
            lista_usuarios = [
                {"id": u.id, "username": u.username, "password": u.password}
                for u in usuarios
            ]
            return jsonify(lista_usuarios)
        return jsonify({"message": "No se encontró ningún usuario"}), 404
    except Exception as e:
        return jsonify({"error": f"Error al obtener los usuarios: {str(e)}"}), 500


@app.route('/usuarios', methods=['GET'])
def listar_usuarios():
    """
    Lista todos los usuarios.
    ---
    responses:
      200:
        description: Lista de usuarios
      404:
        description: No se encontró ningún usuario
      500:
        description: Error al obtener los usuarios
    """
    try:
        usuarios = Session.query(Usuario).all()
        if usuarios:
            lista_usuarios = [
                {"id": u.id, "username": u.username, "password": u.password}
                for u in usuarios
            ]
            return jsonify(lista_usuarios)
        return jsonify({"message": "No se encontró ningún usuario"}), 404
    except Exception as e:
        return jsonify({"error": f"Error al obtener los usuarios: {str(e)}"}), 500

@app.route('/usuario/<int:id>', methods=['PUT'])
def actualizar_usuario(id):
    """
    Actualiza los datos de un usuario por ID.
    ---
    parameters:
      - name: id
        in: path
        type: integer
        required: true
      - name: username
        in: formData
        type: string
        required: false
      - name: password
        in: formData
        type: string
        required: false
    responses:
      200:
        description: Usuario actualizado correctamente
      404:
        description: Usuario no encontrado
    """
    usuario = Session.query(Usuario).filter_by(id=id).first()
    if not usuario:
        return jsonify({"message": "Usuario no encontrado"}), 404
    datos = request.form
    # Validar token
    token = None
    if 'Authorization' in request.headers:
        parts = request.headers['Authorization'].split()
        if len(parts) == 2 and parts[0] == 'Bearer':
            token = parts[1]
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        auth_user = Session.query(Usuario).filter_by(id=data_token['id']).first()
        if not auth_user:
            return jsonify({'message': 'Token inválido (usuario no encontrado)'}), 401
        # Solo admin o el mismo usuario puede actualizar
        if auth_user.rol != 'admin' and auth_user.id != usuario.id:
            return jsonify({'message': 'No tiene permisos para actualizar este usuario'}), 403
        usuario.username = datos.get('username', usuario.username)
        if 'password' in datos:
            password_hash = generate_password_hash(datos['password'], method='pbkdf2:sha256')
            usuario.password = password_hash
        Session.commit()
        return jsonify({"message": "Usuario actualizado correctamente"})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except Exception as e:
        Session.rollback()
        return jsonify({"error": f"Error al actualizar el usuario: {str(e)}"}), 500

@app.route('/usuario/<int:id>', methods=['DELETE'])
def eliminar_usuario(id):
    """
    Elimina un usuario por ID.
    ---
    parameters:
      - name: id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Usuario eliminado correctamente
      404:
        description: Usuario no encontrado
    """
    usuario = Session.query(Usuario).filter_by(id=id).first()
    if not usuario:
        return jsonify({"message": "Usuario no encontrado"}), 404
    # Solo admin puede eliminar
    token = None
    if 'Authorization' in request.headers:
        parts = request.headers['Authorization'].split()
        if len(parts) == 2 and parts[0] == 'Bearer':
            token = parts[1]
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        auth_user = Session.query(Usuario).filter_by(id=data_token['id']).first()
        if not auth_user or auth_user.rol != 'admin':
            return jsonify({'message': 'No autorizado'}), 403
        Session.delete(usuario)
        Session.commit()
        return jsonify({"message": "Usuario eliminado correctamente"})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except Exception as e:
        Session.rollback()
        return jsonify({"error": f"Error al eliminar el usuario: {str(e)}"}), 500

@app.route('/obtener_ventas', methods=['POST'])
def obtener_ventas():
    """
    Obtiene las ventas de un usuario específico.
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
          properties:
            username:
              type: string
              description: Nombre del usuario
              example: "Username"
    responses:
      200:
        description: Ventas encontradas
        schema:
          type: object
          properties:
            usuario:
              type: string
              example: "Username"
            ventas:
              type: array
              items:
                type: number
              example: []
      400:
        description: Nombre de usuario no enviado
        schema:
          type: object
          properties:
            respuesta:
              type: string
      404:
        description: Usuario no encontrado
        schema:
          type: object
          properties:
            error:
              type: string
      500:
        description: Error del servidor
        schema:
          type: object
          properties:
            error:
              type: string
    """
    data = json.loads(request.data)
    if 'username' not in data:
        return jsonify({"respuesta": "Nombre de usuario no enviado, verifica tus datos"}), 400

    # Verificar token y permisos
    token = None
    if 'Authorization' in request.headers:
        parts = request.headers['Authorization'].split()
        if len(parts) == 2 and parts[0] == 'Bearer':
            token = parts[1]
    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    try:
        data_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        auth_user = Session.query(Usuario).filter_by(id=data_token['id']).first()
        if not auth_user:
            return jsonify({'message': 'Token inválido (usuario no encontrado)'}), 401
        if auth_user.rol != 'admin' and auth_user.username != data['username']:
            return jsonify({'message': 'No tiene permisos para ver estas ventas'}), 403
        with engine.connect() as connection:
            busca_usuario = text("SELECT * FROM usuario WHERE username = :username")
            respuesta_usuario = connection.execute(busca_usuario, {"username": data['username']}).first()
            if not respuesta_usuario:
                return jsonify({"error": "Usuario no encontrado"}), 404
            busca_ventas = text("SELECT * FROM ventas WHERE username_id = :username_id")
            respuesta_ventas = connection.execute(busca_ventas, {"username_id": respuesta_usuario.id})
            ventas_lista = [venta.venta for venta in respuesta_ventas]
            return jsonify({
                "usuario": data['username'],
                "ventas": ventas_lista
            })
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    datos = request.form
    username = datos.get('username')
    password = datos.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    user = Session.query(Usuario).filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({
        'id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
    }, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token, 'rol': user.rol})
if __name__ == '__main__':
    # Crear admin por defecto si no existe
    crear_admin_por_defecto()
    app.run(debug=True)