# constants.py
# Constantes para evitar duplicación de literales

# Mensajes de autenticación
TOKEN_MISSING = 'Token is missing!'
TOKEN_EXPIRED = 'Token has expired!'
TOKEN_INVALID_USER = 'Token is invalid (user not found)'
TOKEN_INVALID = 'Token is invalid'

# Mensajes de usuarios
USER_NOT_FOUND = 'Usuario no encontrado'
USER_CREATED = 'Usuario creado correctamente'
USER_UPDATED = 'Usuario actualizado correctamente'
USER_DELETED = 'Usuario eliminado correctamente'
USER_UNAUTHORIZED = 'No autorizado'
USER_NO_PERMISSION = 'No tiene permisos para actualizar este usuario'
USER_NO_PERMISSION_VENTAS = 'No tiene permisos para ver estas ventas'

# Algoritmos de seguridad
PBKDF2_ALGORITHM = 'pbkdf2:sha256'
JWT_ALGORITHM = 'HS256'

# Mensajes de validación
USERNAME_PASSWORD_REQUIRED = 'Username and password required'
INVALID_CREDENTIALS = 'Invalid credentials'
USERNAME_REQUIRED = 'Nombre de usuario no enviado, verifica tus datos'
NO_USERS_FOUND = 'No se encontró ningún usuario'

# Roles
ROLE_ADMIN = 'admin'