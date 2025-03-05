from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Student
from forms import LoginForm, SignupForm, StudentForm
import os

app = Flask(__name__)
app.config.from_object('config.Config')
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('welcome'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    students = []
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        if search_query:
            students = Student.query.filter(Student.name.ilike(f"%{search_query}%")).all()
        else:
            students = Student.query.all()  # Show all records if search is empty
    return render_template('search.html', students=students)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    students = Student.query.all()
    form = StudentForm()

    if form.validate_on_submit():
        new_student = Student(name=form.name.data, diagnosis=form.diagnosis.data)
        db.session.add(new_student)
        db.session.commit()
        flash('Student record added successfully!', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_panel.html', students=students, form=form)

@app.route('/delete/<int:id>')
@login_required
def delete_student(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    student = Student.query.get(id)
    if student:
        db.session.delete(student)
        db.session.commit()
        flash('Student record deleted!', 'success')
    
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
