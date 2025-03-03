from flask import Flask, request, jsonify, session
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
from flask_bcrypt import Bcrypt
from flask_session import Session  

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)  # Allow credentials for session handling
bcrypt = Bcrypt(app)

# Secure Session Configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True 
app.secret_key = os.getenv("SECRET_KEY")

Session(app) 

# Database config
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT')
}

# Connect to database
def get_db_conn():
    try:
        conn = psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)
        print('✔ Database Connected')
        return conn
    except Exception as e:
        print(f'✖ Database connection failed: {e}')
        return None  
    
# Check DB connection
get_db_conn()
    
# Login route
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')
        conn = get_db_conn()
        if not conn:
            return jsonify({'message': 'Database connection failed'}), 500
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM user_list WHERE email = %s OR username = %s',
        (identifier, identifier))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['password'], password):
            role = user['role'].lower()
            session["user"] = {
                'firstname': user['first_name'],
                'lastname': user['last_name'],
                'username': user['username'],
                'contact': user['contact_number'],
                'email': user['email'],
                'user_role': role
            }

            redirect_url = f"#/{role}/dashboard"
            return jsonify({'message': 'Login successful', 'redirect': redirect_url}), 200
        else:
            return jsonify({'message': 'Wrong Email or Password'}), 401
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

# Register route
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        conn = get_db_conn()
        if not conn:
            return jsonify({'message': 'Database connection failed'}), 500
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM user_list WHERE email = %s OR username = %s',
        (data['email'], data['username']))
        if cursor.fetchone():
            return jsonify({'message': 'Email or Username already taken'}), 409
        if len(data['password']) < 8:
            return jsonify({'message': 'Password should be at least 8 characters'}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        cursor.execute(
            'INSERT INTO user_list (first_name, last_name, username, contact_number, email, password) VALUES (%s, %s, %s, %s, %s, %s)',
            (data['first_name'], data['last_name'], data['username'], data['contact_number'], data['email'], hashed_password)
        )
        conn.commit()

        return jsonify({'message': 'Registered Successfully!', 'redirect': '#/login'}), 201
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()

# Check user session
@app.route('/user')
def user():
    if "user" in session:
        return jsonify({'user': session["user"], 'logged_in': True}), 200
    return jsonify({'user': None, 'logged_in': False}), 200

# Client dashboard
@app.route('/client/dashboard')
def client_dashboard():
    if "user" not in session:
        return jsonify({'message': 'Session expired', 'redirect': '#/login'}), 403
    if session['user']['user_role'] != "user":
        return jsonify({'message': 'Access denied', 'redirect': '#/admin/dashboard'}), 403
    return jsonify({'message': 'Welcome to the Client Dashboard', 'user': session['user']}), 200

# Admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if "user" not in session:
        return jsonify({'message': 'Session expired', 'redirect': '#/login'}), 403
    if session['user']['user_role'] != "admin":
        return jsonify({'message': 'Access denied', 'redirect': '#/client/dashboard'}), 403
    return jsonify({'message': 'Welcome to the Admin Dashboard', 'user': session['user']}), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully', 'redirect': '#/login'}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
