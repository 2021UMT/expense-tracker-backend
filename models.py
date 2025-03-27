from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        """Encrypts password before saving it to the database"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Checks if entered password matches the stored password"""
        return bcrypt.check_password_hash(self.password_hash, password)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    date = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('expenses', lazy=True))

