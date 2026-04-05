# =========================================
# Finance Backend (Flask + MySQL) - FINAL
# =========================================

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps

# -------------------------------
# CONFIG
# -------------------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:tiger@localhost/finance_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret123'

# -------------------------------
# INIT
# -------------------------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -------------------------------
# MODELS
# -------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10))
    category = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.String(200))

# -------------------------------
# AUTH FUNCTIONS
# -------------------------------
def generate_token(user):
    payload = {
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=5)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


def token_required(roles=[]):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'error': 'Token missing'}), 401

            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                user = User.query.get(data['user_id'])

                if roles and user.role not in roles:
                    return jsonify({'error': 'Access denied'}), 403

            except:
                return jsonify({'error': 'Invalid token'}), 401

            return func(*args, **kwargs)
        return wrapper
    return decorator

# -------------------------------
# AUTH APIs
# -------------------------------
@app.route('/register', methods=['POST'])
def register():
    data = request.json

    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing fields'}), 400

    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    user = User(
        name=data['name'],
        email=data['email'],
        password=hashed,
        role=data['role']
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered'})


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user)
    return jsonify({'token': token})

# -------------------------------
# RECORD APIs
# -------------------------------
@app.route('/records', methods=['POST'])
@token_required(['admin'])
def create_record():
    data = request.json

    if data['amount'] <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    if data['type'] not in ['income', 'expense']:
        return jsonify({'error': 'Invalid type'}), 400

    record = Record(
        amount=data['amount'],
        type=data['type'],
        category=data['category'],
        notes=data.get('notes', ''),
        date=datetime.strptime(data['date'], '%Y-%m-%d') if data.get('date') else datetime.utcnow()
    )

    db.session.add(record)
    db.session.commit()
    return jsonify({'message': 'Record created'})


@app.route('/records', methods=['GET'])
@token_required(['admin', 'analyst', 'viewer'])
def get_records():
    query = Record.query

    # Filtering
    category = request.args.get('category')
    type_ = request.args.get('type')

    if category:
        query = query.filter_by(category=category)
    if type_:
        query = query.filter_by(type=type_)

    records = query.all()

    return jsonify([{
        'id': r.id,
        'amount': r.amount,
        'type': r.type,
        'category': r.category,
        'date': r.date.strftime('%Y-%m-%d')
    } for r in records])

# -------------------------------
# DASHBOARD APIs
# -------------------------------
@app.route('/summary', methods=['GET'])
@token_required(['admin', 'analyst'])
def summary():
    records = Record.query.all()

    total_income = sum(r.amount for r in records if r.type == 'income')
    total_expense = sum(r.amount for r in records if r.type == 'expense')

    return jsonify({
        'income': total_income,
        'expense': total_expense,
        'balance': total_income - total_expense
    })


@app.route('/recent', methods=['GET'])
@token_required(['admin', 'analyst'])
def recent():
    records = Record.query.order_by(Record.date.desc()).limit(5).all()
    return jsonify([r.category for r in records])


@app.route('/monthly', methods=['GET'])
@token_required(['admin', 'analyst'])
def monthly():
    records = Record.query.all()
    result = {}

    for r in records:
        month = r.date.strftime('%Y-%m')
        result[month] = result.get(month, 0) + r.amount

    return jsonify(result)

# -------------------------------
# INIT DB
# -------------------------------
@app.route('/init')
def init_db():
    db.create_all()
    return "DB Ready"

# -------------------------------
# RUN
# -------------------------------
if __name__ == '__main__':
    app.run(debug=True)
