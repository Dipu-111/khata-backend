from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import hashlib
import jwt
import datetime
from functools import wraps
from datetime import datetime as dt

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="digital_khata"
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate JWT Token
def generate_token(user_id, phone):
    payload = {
        'user_id': user_id,
        'phone': phone,
        'exp': dt.utcnow() + datetime.timedelta(days=7),
        'iat': dt.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Verify JWT Token Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = data['user_id']
            request.user_phone = data['phone']
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return jsonify({'message': 'Digital Khata API is running!'})

# ==================== PUBLIC ROUTES (No Token Required) ====================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        user_id = str(int(dt.now().timestamp() * 1000))
        hashed_pw = hash_password(data['password'])
        
        cursor.execute("""
            INSERT INTO users (id, shop_name, owner_name, phone, password)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, data['shop_name'], data['owner_name'], data['phone'], hashed_pw))
        
        conn.commit()
        
        # Generate token after successful registration
        token = generate_token(user_id, data['phone'])
        
        return jsonify({
            'success': True, 
            'user_id': user_id,
            'token': token
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        hashed_pw = hash_password(data['password'])
        
        cursor.execute("""
            SELECT * FROM users WHERE phone = %s AND password = %s
        """, (data['phone'], hashed_pw))
        
        user = cursor.fetchone()
        
        if user:
            token = generate_token(user['id'], user['phone'])
            return jsonify({
                'success': True, 
                'user': user,
                'token': token
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

# ==================== PROTECTED ROUTES (Token Required) ====================

@app.route('/api/verify', methods=['GET'])
@token_required
def verify_token():
    return jsonify({'success': True, 'user_id': request.user_id})

@app.route('/api/customers', methods=['GET'])
@token_required
def get_customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM customers WHERE user_id = %s", (request.user_id,))
    customers = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return jsonify({'customers': customers})

@app.route('/api/customers', methods=['POST'])
@token_required
def add_customer():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        customer_id = str(int(dt.now().timestamp() * 1000))
        
        cursor.execute("""
            INSERT INTO customers (id, user_id, name, phone, address)
            VALUES (%s, %s, %s, %s, %s)
        """, (customer_id, request.user_id, data['name'], data['phone'], data['address']))
        
        conn.commit()
        return jsonify({'success': True, 'customer_id': customer_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/customers/<customer_id>', methods=['PUT'])
@token_required
def update_customer(customer_id):
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE customers SET name=%s, phone=%s, address=%s
            WHERE id=%s AND user_id=%s
        """, (data['name'], data['phone'], data['address'], customer_id, request.user_id))
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/customers/<customer_id>', methods=['DELETE'])
@token_required
def delete_customer(customer_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM customers WHERE id = %s AND user_id = %s", (customer_id, request.user_id))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("""
        SELECT t.*, c.name as customer_name 
        FROM transactions t
        JOIN customers c ON t.customer_id = c.id
        WHERE t.user_id = %s
        ORDER BY t.date DESC
    """, (request.user_id,))
    
    transactions = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return jsonify({'transactions': transactions})

@app.route('/api/transactions', methods=['POST'])
@token_required
def add_transaction():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        transaction_id = str(int(dt.now().timestamp() * 1000))
        
        cursor.execute("""
            INSERT INTO transactions (id, user_id, customer_id, type, amount, description, date)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (transaction_id, request.user_id, data['customer_id'], 
              data['type'], data['amount'], data['description'], data['date']))
        
        conn.commit()
        return jsonify({'success': True, 'transaction_id': transaction_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/transactions/<transaction_id>', methods=['DELETE'])
@token_required
def delete_transaction(transaction_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            DELETE FROM transactions WHERE id = %s AND user_id = %s
        """, (transaction_id, request.user_id))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/expenses', methods=['GET'])
@token_required
def get_expenses():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM expenses WHERE user_id = %s ORDER BY date DESC", (request.user_id,))
    expenses = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return jsonify({'expenses': expenses})

@app.route('/api/expenses', methods=['POST'])
@token_required
def add_expense():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        expense_id = str(int(dt.now().timestamp() * 1000))
        
        cursor.execute("""
            INSERT INTO expenses (id, user_id, amount, category, date, description, payment_method)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (expense_id, request.user_id, data['amount'], 
              data['category'], data['date'], data['description'], data['payment_method']))
        
        conn.commit()
        return jsonify({'success': True, 'expense_id': expense_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)