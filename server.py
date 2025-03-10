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
Session(app) 

# Secure Session Configuration
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True 
app.secret_key = os.getenv("SECRET_KEY")

app.config.update(
    SESSION_COOKIE_SECURE=True,  # Ensure cookies work over HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",  # Change to "None" if cross-site
)


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
        
        if not user:
            return jsonify({'message': 'There is no such user'}), 404

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
            session.permanent = True
            session.modified = True

            redirect_url = f"/{role}/dashboard"
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

        hashed_password = bcrypt.generate_password_hash(data['password'], 12).decode('utf-8')
        cursor.execute(
            'INSERT INTO user_list (first_name, last_name, username, contact_number, email, password) VALUES (%s, %s, %s, %s, %s, %s)',
            (data['first_name'], data['last_name'], data['username'], data['contact_number'], data['email'], hashed_password)
        )
        conn.commit()

        return jsonify({'message': 'Registered Successfully!', 'redirect': '/login'}), 201
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500
    finally:
        if conn:
            cursor.close()
            conn.close()
            
#update password
@app.route('/change_password', methods=['POST'])
def change_password():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        newPassword = data.get('new_password')
        
        conn = get_db_conn()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM user_list WHERE email = %s', (email,))
            user = cursor.fetchone()

            if user:
                if bcrypt.check_password_hash(user['password'], password) and password == newPassword:
                    return jsonify({'message': 'Old Password cannot be the same as new password'}), 400
            else:
                return jsonify({'message': 'User not found'}), 404

        except Exception as e:
            return jsonify({'error': str(e)}), 500
                
                
        
        cursor.execute('SELECT * FROM user_list WHERE email = %s', (email,))
        user = cursor.fetchone()
        
        if user and bcrypt.check_password_hash(user['password'], password):
            
            hashed_new_password = bcrypt.generate_password_hash(newPassword).decode('utf-8')
            cursor.execute('UPDATE user_list SET password = %s WHERE email = %s', (hashed_new_password, email))
            conn.commit()
            
            return jsonify({'message': 'password changed successfully'}), 200
        else:
            return jsonify({'message': 'Incorrect Email or Password'}), 401
            
    except Exception as e:
        return jsonify({'error': f'Database Error: str{e}'}), 500

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
        return jsonify({'message': 'Session expired', 'redirect': '/login'}), 403
    if session['user']['user_role'] != "user":
        return jsonify({'message': 'Access denied', 'redirect': '/admin/dashboard'}), 403
    return jsonify({'message': 'Welcome to the Client Dashboard', 'user': session['user']}), 200

# Admin dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if "user" not in session:
        return jsonify({'message': 'Session expired', 'redirect': '/login'}), 403
    if session['user']['user_role'] != "admin":
        return jsonify({'message': 'Access denied', 'redirect': '/client/dashboard'}), 403
    return jsonify({'message': 'Welcome to the Admin Dashboard', 'user': session['user']}), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully', 'redirect': '/login'}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
