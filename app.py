from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from models import db, User, Expense
import os
from datetime import datetime, timedelta
import pytz
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from flasgger import Swagger
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


# SECRET_KEY = os.getenv("SECRET_KEY", "Nq8tRf37H")

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "Nq8tRf37H")

DATABASE_URL = "postgresql+psycopg2://postgres:Saurabh123@127.0.0.1:5432/EXPENSE TRACKER"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "supersecretkey"

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

CORS(app)

jwt = JWTManager(app)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Expense Tracker API",
        "description": "API documentation for the Expense Tracker",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
        }
    }
}

swagger = Swagger(app, template=swagger_template)

db.init_app(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()
    print("Database tables created!")

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Expense Tracker API is Running!"}), 200


@app.route('/register', methods=['POST'])
def register():
    """
    User Registration API
    ---
    tags:
      - Authorization
    description: Register a new user by providing name, email, and password
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            name:
              type: string
              example: "Enter your name..."
            email:
              type: string
              example: "Enter your email Id"
            password:
              type: string
              example: "Enter a Strong Password"
    responses:
      201:
        description: User successfully registered
      400:
        description: Invalid input or user already exists
    """
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not (name and email and password):
        return jsonify({"error": "All fields are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    new_user = User(name=name, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    # access_token = create_access_token(identity=str(new_user.id))
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    """
    User Login API
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              example: "saurabhkumar31860@gmail.com"
            password:
              type: string
              example: "Saurabh123"
    responses:
      200:
        description: Login successful, returns JWT token
        schema:
          type: object
          properties:
            message:
              type: string
            access_token:
              type: string
      401:
        description: Unauthorized - Invalid credentials
        schema:
          type: object
          properties:
            error:
              type: string
    """
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"message": "Login successful", "access_token": access_token}), 200


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """Example Protected Route"""
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome User {current_user}! You have access to this route."}), 200


@app.route('/expenses', methods=['GET', 'POST'])
@jwt_required()
def handle_expenses():
    try:
        user_id = get_jwt_identity()

        if request.method == 'GET':
            expenses = Expense.query.filter_by(user_id=user_id).all()
            expenses_list = [{
                "id": exp.id,
                "amount": exp.amount,
                "category": exp.category,
                "description": exp.description,
                "date": exp.date.isoformat()
            } for exp in expenses]

            return jsonify(expenses_list), 200

        elif request.method == 'POST':
            data = request.get_json()

            print("Received data from frontend:", data)

            if not data or 'amount' not in data or 'category' not in data:
                return jsonify({"error": "Missing required fields"}), 400

            date = data.get('date')
            if date:
                date = datetime.strptime(date, "%Y-%m-%d")
            else:
                date = datetime.utcnow()

            new_expense = Expense(
                user_id=user_id,
                amount=data['amount'],
                category=data['category'],
                description=data.get('description', ''),
                date=date
            )
            db.session.add(new_expense)
            db.session.commit()

            return jsonify({"message": "Expense added successfully", "expense_id": new_expense.id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/expenses/<int:expense_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def modify_expense(expense_id):
    try:
        user_id = get_jwt_identity()  
        expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()

        if not expense:
            return jsonify({"error": "Expense not found or unauthorized"}), 404 

        if request.method == 'PUT':
            data = request.get_json()
            if not data:
                return jsonify({"error": "No data provided"}), 400

            expense.amount = data.get('amount', expense.amount)
            expense.category = data.get('category', expense.category)
            expense.description = data.get('description', expense.description)

            if 'date' in data:  
                local_tz = pytz.timezone("Asia/Kolkata")
                expense.date = datetime.strptime(data['date'], "%Y-%m-%d").replace(tzinfo=pytz.utc).astimezone(local_tz)

            db.session.commit()
            return jsonify({"message": "Expense updated successfully"}), 200

        elif request.method == 'DELETE':
            db.session.delete(expense)
            db.session.commit()
            return jsonify({"message": "Expense deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    """
    Retrieve all expenses
    ---
    tags:
      - Expenses
    security:
      - Bearer: []  
    description: Returns a list of all expenses stored in the database for the logged-in user
    responses:
      200:
        description: A list of expenses
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                description: Expense ID
              amount:
                type: number
                description: Expense amount
              category:
                type: string
                description: Category of the expense
              date:
                type: string
                description: Date of the expense
      401:
        description: Unauthorized - Missing or invalid token
    """

@app.route('/expenses', methods=['POST'])
@jwt_required()
def add_expense():
    """
    Add a new expense
    ---
    tags:
      - Expenses
    description: Adds a new expense to the database
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            amount:
              type: number
              description: Expense amount
              required: true
            category:
              type: string
              description: Category of the expense
              required: true
            description:
              type: string
              description: Description of the expense
            date:
              type: string
              format: date
              description: Date of the expense (YYYY-MM-DD)
    responses:
      201:
        description: Expense created successfully
        schema:
          type: object
          properties:
            user_id:
              type: integer
              description: ID of the created expense
            amount:
              type: number
              description: Expense amount
            category:
              type: string
              description: Expense category
            description:
              type: string
              description: Expense description
            date:
              type: string
              format: date
              description: Date of the expense
      400:
        description: Invalid input data
    """

@app.route('/expenses/<int:expense_id>', methods=['PUT'])
@jwt_required()
def update_expense(expense_id):
    """
    Update an existing expense
    ---
    tags:
      - Expenses
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: "Bearer <JWT Token>"
      - name: expense_id
        in: path
        type: integer
        required: true
        description: ID of the expense to update
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            amount:
              type: number
              description: Updated amount of the expense
            category:
              type: string
              description: Updated category of the expense
            date:
              type: string
              format: date
              description: Updated date of the expense in 'YYYY-MM-DD' format
    responses:
      200:
        description: Expense updated successfully
      400:
        description: Bad request, validation failed
      404:
        description: Expense not found
      500:
        description: Internal server error
    """

@app.route('/expenses/<int:expense_id>', methods=['DELETE'])
@jwt_required()
def delete_expense(expense_id):
    """
    Delete an expense
    ---
    tags:
      - Expenses
    description: Delete an expense by its ID
    parameters:
      - name: expense_id
        in: path
        type: integer
        required: true
        description: ID of the expense to delete
    responses:
      200:
        description: Expense deleted successfully
      404:
        description: Expense not found
    security:
      - Bearer: []
    """

@app.route('/reset-password-request', methods=['POST'])
def reset_password_request():
    data = request.json
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if user:
        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = f"http://localhost:3000/reset-password/{token}"  # URL to be used in frontend

        # Send email with reset URL
        msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Please click the link to reset your password: {reset_url}'
        mail.send(msg)
        
        return jsonify({"message": "Password reset email sent successfully"}), 200
    else:
        return jsonify({"message": "Email not found"}), 404
    


@app.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Reset Password API
    ---
    tags:
      - Authorization
    description: Reset the user's password using the provided token and new password
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            token:
              type: string
              example: "token_string_here"
            new_password:
              type: string
              example: "NewPassword123"
    responses:
      200:
        description: Password reset successful
      400:
        description: Invalid token or expired
      404:
        description: User not found
    """
    data = request.json
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400

    try:
        # Decode the token
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token expires in 1 hour
    except SignatureExpired:
        return jsonify({"error": "The reset link has expired. Please try again."}), 400
    except Exception:
        return jsonify({"error": "Invalid token"}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Update user's password
    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password reset successful"}), 200



if __name__ == '__main__':
    app.run(debug=True)
