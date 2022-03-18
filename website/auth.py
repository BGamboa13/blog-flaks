from flask import Blueprint, render_template, redirect, url_for, request, flash
from . import db
from .models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Conectado!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('La contraseña es incorrecta.', category='error')
        else:
            flash('El correo electrónico no existe.', category='error')
            
    return render_template("login.html", user=current_user)

@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        
        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()
        if email_exists:
            flash('Correo electrónico ya está en uso.', category='error')
        elif username_exists:
            flash('El nombre de usuario ya está en uso.', category='error')
        elif password1 != password2:
            flash('La contraseña no coincide!', category='error')
        elif len(username) < 2:
            flash('El nombre de usuario es demasiado corto.', category='error')
        elif len(password1) < 4:
            flash('La contraseña es demasiado corta.', category='error')
        elif len(email) < 4:
            flash("el correo electrónico es invalido.", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Usuario creado!')
            return redirect(url_for('views.home'))
    
    return render_template("signup.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("views.home"))