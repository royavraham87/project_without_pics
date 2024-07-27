from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
import pytz
import jwt
from functools import wraps

# Initialize Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
app.config['SECRET_KEY'] = 'jwtsecretkey'  # Secret key for JWT

# Initialize extensions
db = SQLAlchemy(app)  # Database ORM
bcrypt = Bcrypt(app)  # Password hashing

# Set the local time zone (UTC+3)
local_tz = pytz.timezone('Etc/GMT-3')

# Function to get the current local time
def get_local_time():
    return datetime.now(local_tz)

# Function to format the date and time as YYYY-MM-DD HH:MM:SS
def format_datetime(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')

# Function to generate JWT token
def generate_jwt(user_id, role):
    utc_now = datetime.now(timezone.utc)
    expiration_time = utc_now + timedelta(hours=1)
    
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': expiration_time
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Decorator to protect routes with JWT
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            token = token.split()[1]  # Split "Bearer <token>" to get the actual token
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['user_id']
            request.role = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated_function


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    age = db.Column(db.Integer, nullable=True)
    loans = db.relationship('Loan', backref='user', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    loan_type = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='available', nullable=False)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    loan_date = db.Column(db.String(20), nullable=False)
    return_date = db.Column(db.String(20), nullable=False)
    actual_return_date = db.Column(db.String(20), nullable=True)
    username = db.Column(db.String(50), nullable=False)
    user_name = db.Column(db.String(100), nullable=True)
    book_name = db.Column(db.String(100), nullable=False)

class LateLoan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    late_days = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    user_name = db.Column(db.String(100), nullable=True)
    book_name = db.Column(db.String(100), nullable=False)

# Helper function to get return date based on loan type
def get_return_date(loan_type):
    if loan_type == 1:
        return get_local_time() + timedelta(days=10)
    elif loan_type == 2:
        return get_local_time() + timedelta(days=5)
    elif loan_type == 3:
        return get_local_time() + timedelta(days=2)
    elif loan_type == 4:
        return get_local_time() + timedelta(minutes=5)

# Function to convert User to dictionary
def user_to_dict(user):
    return {
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'name': user.name,
        'city': user.city,
        'age': user.age
    }

# Function to convert Book to dictionary
def book_to_dict(book):
    return {
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'year_published': book.year_published,
        'loan_type': book.loan_type,
        'status': book.status
    }

# Function to convert Loan to dictionary
def loan_to_dict(loan):
    return {
        'id': loan.id,
        'user_id': loan.user_id,
        'book_id': loan.book_id,
        'loan_date': loan.loan_date,
        'return_date': loan.return_date,
        'actual_return_date': loan.actual_return_date,
        'username': loan.username,
        'user_name': loan.user_name,
        'book_name': loan.book_name
    }

@app.route('/')
def hello():
    return 'Let the library testing begin!!!!!'

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'customer')  # Default role to 'customer' if not provided

    # Optional fields
    name = data.get('name', '')
    city = data.get('city', '')
    age = data.get('age', -1)

    if role not in ['admin', 'customer']:
        return jsonify({'message': 'Invalid role provided'}), 400

    if username and password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role=role, name=name, city=city, age=age)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(user_to_dict(new_user)), 201
    else:
        return jsonify({'message': 'Username and password are required'}), 400


# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = generate_jwt(user.id, user.role)
        return jsonify({'token': token, 'role': user.role}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    # Invalidate the token by making it expired (client should handle it by removing the token)
    return jsonify({"message": "Logged out successfully"})

# Route to loan a book
@app.route('/loan_book', methods=['POST'])
@jwt_required
def loan_book():
    if request.role == 'customer':
        data = request.get_json()
        book = Book.query.get(data['book_id'])
        if book and book.status == 'available':
            loan_date = format_datetime(get_local_time())
            return_date = format_datetime(get_return_date(book.loan_type))
            user = User.query.get(request.user_id)
            new_loan = Loan(
                user_id=request.user_id, 
                book_id=book.id, 
                loan_date=loan_date, 
                return_date=return_date, 
                username=user.username,
                user_name=user.name,
                book_name=book.name
            )
            book.status = 'on loan'
            db.session.add(new_loan)
            db.session.commit()
            return jsonify(loan_to_dict(new_loan))
        else:
            return jsonify({"message": "Book not available"}), 400
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route to return a book
@app.route('/return_book', methods=['POST'])
@jwt_required
def return_book():
    if request.role == 'customer':
        data = request.get_json()
        loan = Loan.query.filter_by(book_id=data['book_id'], user_id=request.user_id, actual_return_date=None).first()
        if loan:
            loan.actual_return_date = format_datetime(get_local_time())
            book = Book.query.get(loan.book_id)
            book.status = 'available'
            db.session.commit()
            
            # Check if the return is late
            if datetime.strptime(loan.actual_return_date, '%Y-%m-%d %H:%M:%S') > datetime.strptime(loan.return_date, '%Y-%m-%d %H:%M:%S'):
                late_days = (datetime.strptime(loan.actual_return_date, '%Y-%m-%d %H:%M:%S') - datetime.strptime(loan.return_date, '%Y-%m-%d %H:%M:%S')).days
                late_loan = LateLoan(
                    loan_id=loan.id,
                    user_id=loan.user_id,
                    username=loan.username,
                    user_name=loan.user_name,
                    book_id=loan.book_id,
                    book_name=loan.book_name,
                    late_days=late_days
                )
                db.session.add(late_loan)
                db.session.commit()
                
            return jsonify(loan_to_dict(loan))
        else:
            return jsonify({"message": "Loan record not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to get current active loans
@app.route('/loans', methods=['GET'])
@jwt_required
def get_active_loans():
    if request.role == 'admin':
        loans = Loan.query.filter_by(actual_return_date=None).all()
        return jsonify([loan_to_dict(loan) for loan in loans])
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to get all loans (loan history)
@app.route('/loan_his', methods=['GET'])
@jwt_required
def get_loan_history():
    if request.role == 'admin':
        loans = Loan.query.all()
        return jsonify([loan_to_dict(loan) for loan in loans])
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to get late loans
@app.route('/late_loans', methods=['GET'])
@jwt_required
def get_late_loans():
    if request.role == 'admin':
        loans = Loan.query.filter(Loan.actual_return_date > Loan.return_date).all()
        return jsonify([loan_to_dict(loan) for loan in loans])
    else:
        return jsonify({"message": "Unauthorized"}), 403


# Route for admin to add a user
@app.route('/add_user', methods=['POST'])
@jwt_required
def add_user():
    if request.role == 'admin':
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(
            username=data['username'],
            password=hashed_password,
            role=data['role'],
            name=data.get('name', ''),  # Use get with a default value
            city=data.get('city', ''),  # Use get with a default value
            age=data.get('age', -1)     # Use get with a default value
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify(user_to_dict(new_user))
    else:
        return jsonify({"message": "Unauthorized"}), 403


# Route for admin to add a book
@app.route('/add_book', methods=['POST'])
@jwt_required
def add_book():
    if request.role == 'admin':
        data = request.get_json()
        new_book = Book(name=data['name'], author=data['author'], year_published=data['year_published'], loan_type=data['loan_type'])
        db.session.add(new_book)
        db.session.commit()
        return jsonify(book_to_dict(new_book))
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route to get all books
@app.route('/books', methods=['GET'])
@jwt_required
def get_books():
    books = Book.query.all()
    return jsonify([book_to_dict(book) for book in books])

# Route for admin to get all customers
@app.route('/customers', methods=['GET'])
@jwt_required
def get_customers():
    if request.role == 'admin':
        users = User.query.all()
        return jsonify([user_to_dict(user) for user in users])
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to delete a customer
@app.route('/delete_customer/<int:id>', methods=['DELETE'])
@jwt_required
def delete_customer(id):
    if request.role == 'admin':
        user = User.query.get(id)
        if user and user.role == 'customer':
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": "Customer deleted successfully"})
        return jsonify({"message": "Customer not found or unauthorized"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to update a customer
@app.route('/update_customer/<int:id>', methods=['PUT'])
@jwt_required
def update_customer(id):
    if request.role == 'admin':
        user = User.query.get(id)
        if user:
            data = request.get_json()
            user.username = data.get('username', user.username)
            if 'password' in data:
                user.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            user.role = data.get('role', user.role)
            user.name = data.get('name', user.name)
            user.city = data.get('city', user.city)
            user.age = data.get('age', user.age)
            db.session.commit()
            return jsonify(user_to_dict(user))
        else:
            return jsonify({"message": "User not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to delete a book
@app.route('/delete_book/<int:id>', methods=['DELETE'])
@jwt_required
def delete_book(id):
    if request.role == 'admin':
        book = Book.query.get(id)
        if book:
            db.session.delete(book)
            db.session.commit()
            return jsonify(book_to_dict(book))
        else:
            return jsonify({"message": "Book not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to update a book
@app.route('/update_book/<int:id>', methods=['PUT'])
@jwt_required
def update_book(id):
    if request.role == 'admin':
        book = Book.query.get(id)
        if book:
            data = request.get_json()
            book.name = data.get('name', book.name)
            book.author = data.get('author', book.author)
            book.year_published = data.get('year_published', book.year_published)
            book.loan_type = data.get('loan_type', book.loan_type)
            db.session.commit()
            return jsonify(book_to_dict(book))
        else:
            return jsonify({"message": "Book not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

@app.route('/find_book', methods=['GET', 'POST'])
@jwt_required
def find_book():
    if request.method == 'GET':
        query = request.args.get('query', '')
    elif request.method == 'POST':
        data = request.get_json()
        query = data.get('query', '')

    books = Book.query.filter(Book.name.ilike(f'%{query}%')).all()
    return jsonify([book_to_dict(book) for book in books])

# Route to find a customer by name
@app.route('/find_customer', methods=['GET', 'POST'])
@jwt_required
def find_customer():
    if request.method == 'POST':
        data = request.get_json()
        query = data.get('query', '')
    else:
        query = request.args.get('query', '')
        
    customers = User.query.filter(User.name.ilike(f'%{query}%'), User.role == 'customer').all()
    return jsonify([user_to_dict(customer) for customer in customers])


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
