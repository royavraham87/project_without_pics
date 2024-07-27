from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta, timezone
import pytz
import jwt
from functools import wraps
from flask_cors import CORS

# Initialize Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
app.config['SECRET_KEY'] = 'jwtsecretkey'  # Secret key for JWT

# Enable CORS for all routes and origins
CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:5501"}})

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
    first_name = db.Column(db.String(100), nullable=True, default='Guest')
    last_name = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    age = db.Column(db.Integer, nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(100), nullable=True)
    active = db.Column(db.String(20), default='active', nullable=False)
    loans = db.relationship('Loan', backref='user', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    loan_type = db.Column(db.Integer, nullable=False)
    active = db.Column(db.String(20), default='active', nullable=False)
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
        'first_name': user.first_name,
        'last_name': user.last_name,
        'city': user.city,
        'age': user.age,
        'phone_number': user.phone_number,
        'email': user.email,
        'active': user.active
    }

# Function to convert Book to dictionary
def book_to_dict(book):
    return {
        'id': book.id,
        'name': book.name,
        'author': book.author,
        'year_published': book.year_published,
        'loan_type': book.loan_type,
        'status': book.status,
        'active': book.active
    }

# Function to convert Loan to dictionary
def loan_to_dict(loan):
    user = User.query.get(loan.user_id)
    book = Book.query.get(loan.book_id)
    return {
        'id': loan.id,
        'user_id': loan.user_id,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'book_id': loan.book_id,
        'book_name': book.name,
        'loan_date': loan.loan_date,
        'return_date': loan.return_date,
        'actual_return_date': loan.actual_return_date,
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

    if role not in ['admin', 'customer']:
        return jsonify({'message': 'Invalid role provided'}), 400

    if username and password:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(user_to_dict(new_user)), 201
    else:
        return jsonify({'message': 'Username and password are required'}), 400

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"message": "Invalid request"}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = generate_jwt(user.id, user.role)
        return jsonify({'token': token, 'role': user.role}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Route to get and update user profile
@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required
def manage_profile():
    current_user_id = request.user_id
    current_role = request.role

    if current_role == 'customer' or current_role == 'admin':
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"message": "User not found"}), 404

        if request.method == 'GET':
            # Return user profile information
            return jsonify(user_to_dict(user)), 200

        elif request.method == 'PUT':
            # Update user's profile fields
            data = request.get_json()
            user.first_name = data.get('first_name', user.first_name)
            user.last_name = data.get('last_name', user.last_name)
            user.phone_number = data.get('phone_number', user.phone_number)
            user.email = data.get('email', user.email)
            user.age = data.get('age', user.age)
            user.city = data.get('city', user.city)
            db.session.commit()
            return jsonify({"message": "Profile updated successfully", "user": user_to_dict(user)}), 200
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    # Invalidate the token by making it expired (client should handle it by removing the token)
    return jsonify({"message": "Logged out successfully"})

# Route to loan a book
@app.route('/loan_book', methods=['POST'])
@jwt_required
def loan_book():
    current_user_id = request.user_id
    current_role = request.role

    if current_role == 'customer':
        data = request.get_json()
        book = Book.query.get(data['book_id'])
        user = User.query.get(current_user_id)
        
        if user.active == 'inactive':
            return jsonify({"message": "User is inactive"}), 400
        
        if book:
            if book.status == 'available' and book.active == 'active':
                loan_date = format_datetime(get_local_time())
                return_date = format_datetime(get_return_date(book.loan_type))
                new_loan = Loan(
                    user_id=current_user_id, 
                    book_id=book.id, 
                    loan_date=loan_date, 
                    return_date=return_date, 
                    username=user.username,
                    user_name=user.first_name,
                    book_name=book.name
                )
                book.status = 'on loan'
                db.session.add(new_loan)
                db.session.commit()
                return jsonify(loan_to_dict(new_loan))
            elif book.active == 'inactive':
                return jsonify({"message": "Book is inactive"}), 400
            else:
                return jsonify({"message": "Book not available"}), 400
        else:
            return jsonify({"message": "Book not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route to return a book
@app.route('/return_book', methods=['POST'])
@jwt_required
def return_book():
    if request.role == 'customer':
        data = request.get_json()
        loan = Loan.query.filter_by(book_id=data['book_id'], user_id=request.user_id, actual_return_date=None).first()
        
        # Check if there is no loan record found, and return an error message early
        if not loan:
            return jsonify({"message": "You didn't loan this book and cannot return it"}), 404

        # Process the return since loan exists
        loan.actual_return_date = format_datetime(get_local_time())
        book = Book.query.get(loan.book_id)
        book.status = 'available'
        db.session.commit()
        
        # Check if the return is late and handle accordingly
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
        return jsonify({"message": "Unauthorized"}), 403

@app.route('/loans', methods=['GET'])
@jwt_required
def get_active_loans():
    try:
        current_user_id = request.user_id
        current_role = request.role

        if current_role != 'admin' and current_role != 'customer':
            return jsonify({'message': 'Permission denied'}), 403

        if current_role == 'admin':
            loans = db.session.query(Loan, User).join(User, Loan.user_id == User.id).filter(Loan.actual_return_date == None).all()
        else:
            loans = db.session.query(Loan).filter(Loan.user_id == current_user_id, Loan.actual_return_date == None).all()

        if not loans:
            return jsonify({'message': 'No active loans found'}), 404

        loan_list = []
        for loan in loans:
            if current_role == 'admin':
                loan, user = loan
                user_info = {
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            else:
                user_info = {}

            book = Book.query.get(loan.book_id)
            loan_date = datetime.strptime(loan.loan_date, '%Y-%m-%d %H:%M:%S')
            return_date = datetime.strptime(loan.return_date, '%Y-%m-%d %H:%M:%S')
            is_late = datetime.now() > return_date
            loan_data = {
                'loan_id': loan.id,
                'book_id': loan.book_id,
                'book_name': book.name,
                'loan_date': loan.loan_date,
                'return_date': loan.return_date,
                'is_late': is_late,
                **user_info  # Include user information only if it exists
            }
            loan_list.append(loan_data)

        return jsonify({'active_loans': loan_list}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/loan_his', methods=['GET'])
@jwt_required
def get_loan_history():
    try:
        current_user_id = request.user_id
        current_role = request.role
        
        if current_role != 'admin' and current_role != 'customer':
            return jsonify({'message': 'Permission denied'}), 403
        
        if current_role == 'admin':
            loans = Loan.query.all()
        else:
            loans = Loan.query.filter_by(user_id=current_user_id).all()

        if not loans:
            return jsonify({'message': 'No loan history found'}), 404

        loan_history = []
        for loan in loans:
            book = Book.query.get(loan.book_id)
            user = User.query.get(loan.user_id)
            loan_data = {
                'loan_id': loan.id,
                'book_id': loan.book_id,
                'book_name': book.name,
                'loan_date': loan.loan_date,
                'return_date': loan.return_date,
                'actual_return_date': loan.actual_return_date
            }

            if current_role == 'admin':
                loan_data.update({
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                })

            loan_history.append(loan_data)

        return jsonify({'loan_history': loan_history}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route for admin to get late loans
@app.route('/late_loans', methods=['GET'])
@jwt_required
def get_late_loans():
    if request.role == 'admin':
        loans = Loan.query.filter(Loan.actual_return_date > Loan.return_date).all()
        return jsonify([loan_to_dict(loan) for loan in loans])
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route for admin to add a book
@app.route('/add_book', methods=['POST'])
@jwt_required
def add_book():
    if request.role == 'admin':
        data = request.get_json()
        try:
            year_published = int(data['year_published'])  # Ensure year_published is an integer
        except ValueError:
            return jsonify({"message": "year_published must be an integer"}), 400
        
        new_book = Book(name=data['name'], author=data['author'], year_published=year_published, loan_type=data['loan_type'])
        db.session.add(new_book)
        db.session.commit()
        return jsonify(book_to_dict(new_book))
    else:
        return jsonify({"message": "Unauthorized"}), 403

# Route to get all books
@app.route('/books', methods=['GET'])
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

# Route for admin to toggle customer active status
@app.route('/toggle_customer/<int:id>', methods=['POST'])
@jwt_required
def toggle_customer(id):
    if request.role == 'admin':
        # Prevent admin from toggling themselves
        if request.user_id == id:
            return jsonify({"message": "Admin cannot toggle themselves"}), 400

        user = User.query.get(id)
        if user and user.role == 'customer':
            active_loans = Loan.query.filter_by(user_id=id, actual_return_date=None).count()
            if user.active == 'active' and active_loans > 0:
                return jsonify({"message": "User has active loans and cannot be deactivated"}), 400
            user.active = 'inactive' if user.active == 'active' else 'active'
            db.session.commit()
            return jsonify(user_to_dict(user))
        return jsonify({"message": "Customer not found or unauthorized"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403


# Route for admin to toggle book active status
@app.route('/toggle_book/<int:id>', methods=['POST'])
@jwt_required
def toggle_book(id):
    if request.role == 'admin':
        book = Book.query.get(id)
        if book:
            active_loans = Loan.query.filter_by(book_id=id, actual_return_date=None).count()
            if book.active == 'active' and active_loans > 0:
                return jsonify({"message": "Book is currently on loan and cannot be deactivated"}), 400
            book.active = 'inactive' if book.active == 'active' else 'active'
            book.status = 'available' if book.active == 'active' else 'unavailable'
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

@app.route('/book/<int:id>', methods=['GET'])
@jwt_required
def get_book(id):
    if request.role == 'admin':
        book = Book.query.get(id)
        if book:
            return jsonify(book_to_dict(book))
        else:
            return jsonify({"message": "Book not found"}), 404
    else:
        return jsonify({"message": "Unauthorized"}), 403


@app.route('/find_book', methods=['GET', 'POST'])
def find_book():
    if request.method == 'GET':
        name = request.args.get('name', '')
        author = request.args.get('author', '')
    elif request.method == 'POST':
        data = request.get_json()
        name = data.get('name', '')
        author = data.get('author', '')

    query = Book.query
    if name:
        query = query.filter(Book.name.ilike(f'%{name}%'))
    if author:
        query = query.filter(Book.author.ilike(f'%{author}%'))

    books = query.all()
    return jsonify([book_to_dict(book) for book in books])


# Route to find a customer by first or last name
@app.route('/find_customer', methods=['GET', 'POST'])
@jwt_required
def find_customer():
    if request.role != 'admin':
        return jsonify({"message": "Unauthorized"}), 403

    if request.method == 'POST':
        data = request.get_json()
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')
    else:
        first_name = request.args.get('first_name', '')
        last_name = request.args.get('last_name', '')
        
    query = User.query
    if first_name:
        query = query.filter(User.first_name.ilike(f'%{first_name}%'))
    if last_name:
        query = query.filter(User.last_name.ilike(f'%{last_name}%'))

    users = query.all()
    return jsonify([user_to_dict(user) for user in users])



if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
