from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect password", category='error')
                return redirect(url_for('auth.login'))
        else:
            flash("Email does not exist", category='error')
            return redirect(url_for('auth.login'))
                
    return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Email already exists", category='error')
        elif len(email) < 4:
            flash("Email must be greater than 4 characters", category='error')
        elif len(name) < 2:
            flash("Name must be at least 2 characters", category='error')
        elif password1 != password2:
            flash("Your passwords do not match", category='error')
        elif len(password1) < 7:
            flash("Password must be at least 7 characters", category='error')
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash("Account created successfully", category='success')
            return redirect(url_for('views.home'))


    return render_template("signup.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():    
    logout_user()
    return redirect(url_for('auth.login'))
