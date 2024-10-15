from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import os
import smtplib
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

app = Flask(__name__)

# Conexión con MongoDB usando la URI de conexión
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client['multifactor']
users_collection = db['users']

# Configuración del servidor SMTP
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Función para enviar correo
def send_verification_email(to_email, code):
    subject = 'Tu código de verificación'
    message = f'Hola, tu código de verificación es: {code}'
    
    # Crear el mensaje
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    # Agregar el cuerpo del mensaje
    msg.attach(MIMEText(message, 'plain'))

    try:
        # Conectar al servidor de Gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_USER, to_email, text)
        server.quit()
        print('Correo enviado exitosamente')
    except Exception as e:
        print(f'Error al enviar correo: {e}')

# Ruta para registrar a un nuevo usuario
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email y contraseña son requeridos'}), 400

    # Verificar si el usuario ya existe
    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'El usuario ya existe'}), 400

    # Hashear la contraseña
    password_hash = generate_password_hash(password)

    # Insertar el nuevo usuario en la base de datos
    new_user = {
        'email': email,
        'password_hash': password_hash,
        'verification_code': None,
        'code_expires_at': None
    }
    users_collection.insert_one(new_user)

    return jsonify({'message': 'Usuario registrado correctamente'}), 201

# Ruta para enviar el código de verificación al iniciar sesión
@app.route('/send-code', methods=['POST'])
def send_verification_code():
    data = request.get_json()
    email = data.get('email')

    # Verificar si el usuario existe
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    # Generar un código de verificación
    verification_code = str(random.randint(100000, 999999))
    code_expires_at = datetime.utcnow() + timedelta(minutes=10)

    # Actualizar el usuario con el código de verificación
    users_collection.update_one(
        {'email': email},
        {'$set': {'verification_code': verification_code, 'code_expires_at': code_expires_at}}
    )

    # Enviar el código por correo
    send_verification_email(email, verification_code)

    return jsonify({'message': 'Código de verificación enviado al correo'}), 200

# Ruta para verificar el código de inicio de sesión
@app.route('/verify-code', methods=['POST'])
def verify_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    # Verificar si el usuario existe
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    # Verificar si el código es correcto y no ha expirado
    if user['verification_code'] == code and datetime.utcnow() < user['code_expires_at']:
        return jsonify({'message': 'Código verificado correctamente'}), 200
    else:
        return jsonify({'error': 'Código inválido o expirado'}), 400

# Ruta para iniciar sesión
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Verificar si el usuario existe
    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404

    # Verificar si la contraseña es correcta
    if check_password_hash(user['password_hash'], password):
        return jsonify({'message': 'Inicio de sesión exitoso'}), 200
    else:
        return jsonify({'error': 'Contraseña incorrecta'}), 400

# Inicio del servidor
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
