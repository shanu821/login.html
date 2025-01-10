from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'  # Using SQLite for simplicity
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Models

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(400))
    role = db.Column(db.String(20))  # normal user, admin, store_owner

class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(400), nullable=False)
    users_rated = db.relationship('Rating', backref='store', lazy=True)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating_value = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)

# Authentication and Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        address = request.form['address']
        role = 'normal'  # Default role for new users
        new_user = User(name=name, email=email, password=password, address=address, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        total_users = User.query.count()
        total_stores = Store.query.count()
        total_ratings = Rating.query.count()
        return render_template('admin_dashboard.html', total_users=total_users, total_stores=total_stores, total_ratings=total_ratings)
    
    elif current_user.role == 'store_owner':
        stores = Store.query.filter_by(owner_id=current_user.id).all()
        return render_template('store_owner_dashboard.html', stores=stores)
    
    else:
        stores = Store.query.all()
        return render_template('user_dashboard.html', stores=stores)

@app.route('/rate_store/<int:store_id>', methods=['GET', 'POST'])
@login_required
def rate_store(store_id):
    store = Store.query.get(store_id)
    if request.method == 'POST':
        rating_value = request.form['rating']
        rating = Rating.query.filter_by(user_id=current_user.id, store_id=store_id).first()
        if rating:
            rating.rating_value = rating_value
        else:
            new_rating = Rating(rating_value=rating_value, user_id=current_user.id, store_id=store_id)
            db.session.add(new_rating)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('rate_store.html', store=store)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
