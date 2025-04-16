from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random
import string
import os


app = Flask(__name__)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blink2educarrer.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///fallback.db")
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.app_context().push()
# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Quiz Model
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(10), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Question Model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)

# Attempt Model
class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

def generate_quiz_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    quizzes = quizzes = Quiz.query.filter_by(created_by=current_user.id).all()
    return render_template('dashboard.html', quizzes=quizzes)

@app.route('/create_quiz', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if request.method == 'POST':
        title = request.form['title']
        code = generate_quiz_code()
        new_quiz = Quiz(title=title, code=code, created_by=current_user.id)
        db.session.add(new_quiz)
        db.session.commit()
        return redirect(url_for('add_questions', quiz_id=new_quiz.id))
    return render_template('create_quiz.html')



@app.route('/add_questions/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def add_questions(quiz_id):
    if request.method == 'POST':
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_option = request.form['correct_option']
        new_question = Question(quiz_id=quiz_id, question_text=question_text, option_a=option_a, option_b=option_b,
                                option_c=option_c, option_d=option_d, correct_option=correct_option)
        db.session.add(new_question)
        db.session.commit()
        if 'finish' in request.form:
            return redirect(url_for('dashboard'))
    return render_template('add_questions.html', quiz_id=quiz_id)


@app.route('/attempt_quiz', methods=['GET', 'POST'])
def attempt_quiz():
    if request.method == 'POST':
        quiz_code = request.form['quiz_code']
        quiz = Quiz.query.filter_by(code=quiz_code).first()
        if quiz:
            return redirect(url_for('take_quiz', quiz_id=quiz.id))
    return render_template('attempt_quiz.html')


@app.route('/take_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz.id).all()
    if request.method == 'POST':
        score = 0
        for question in questions:
            selected_option = request.form.get(str(question.id))
            if selected_option == question.correct_option:
                score += 1
        if current_user.is_authenticated:
            attempt = Attempt(quiz_id=quiz.id, user_id=current_user.id, score=score)
            db.session.add(attempt)
            db.session.commit()
        return redirect(url_for('view_scores', quiz_id=quiz.id))
    return render_template('take_quiz.html', quiz=quiz, questions=questions)

@app.route('/view_scores/<int:quiz_id>')
@login_required
def view_scores(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    attempts = Attempt.query.filter_by(quiz_id=quiz.id).all()
    return render_template('view_scores.html', quiz=quiz, attempts=attempts)


@app.before_first_request
def create_tables():
    db.create_all()
    
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
