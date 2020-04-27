from flask import Flask, render_template, redirect, url_for, flash, send_file
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length
from wtforms.widgets import TextArea
from modules.db_engine import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date
from modules.email_module import if_valid_add


app = Flask(__name__)
app.config.from_pyfile('modules/config.cfg')
db.init_app(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True)
    create_date = db.Column(db.DateTime)
    stories = db.relationship('Story', backref='owner', lazy='dynamic')


class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    story = db.Column(db.Text)
    publish_date = db.Column(db.DateTime)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    story_id = db.Column(db.Integer)
    comments = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=120)])
    password = PasswordField('password', validators=[InputRequired(), Length(max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=25)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=120)])


class ChangePasswordForm(FlaskForm):
    old_pass = PasswordField('old_password', validators=[InputRequired()])
    new_pass = PasswordField('new_password', validators=[InputRequired(), Length(min=8, max=80)])


class DeleteStoryForm(FlaskForm):
    story_id = IntegerField('story_id', validators=[InputRequired()])


class PostStoryForm(FlaskForm):
    story_txt = StringField('Story Text', validators=[InputRequired()], widget=TextArea())


@app.route('/')
def index():
    return render_template('main.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                db.session.close()
                return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, create_date=date.today())
        exist = User.query.filter_by(email=form.email.data).first()
        if exist:
            flash('Email already Exist')
        elif 'OK' == if_valid_add(form.email.data):
            db.session.add(new_user)
            db.session.commit()
            flash('User has been created...!')
        flash('Mail not exit in server')

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    story_data = db.session.query(User.username, Story.story).filter(User.id == Story.user_id).all()
    return render_template('userdash.html', name=current_user.username, data=story_data)




@app.route('/profile')
@login_required
def profile():
    user_data = User.query.filter_by(email=current_user.email).first()
    name = user_data.username
    email = user_data.email
    created = str(user_data.create_date).split(' ')
    return render_template('profile.html', name=name, email=email, created=created[0])


@app.route('/change_pass', methods=['GET', 'POST'])
@login_required
def change_pass():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_pass.data):
            password = generate_password_hash(form.new_pass.data, method='sha256')
            current_user.password = password
            db.session.commit()
            flash('Password has been changed')
        flash('Current password is wrong')
    return render_template('change_pass.html',form=form)


@app.route('/post_story', methods=['GET', 'POST'])
@login_required
def post_story():
    form = PostStoryForm()
    if form.validate_on_submit():
        add_story = Story(owner=current_user, story=form.story_txt.data, publish_date=date.today())
        db.session.add(add_story)
        db.session.commit()
        flash('Story added')
    return render_template('post_story.html', form=form)


@app.route('/delete_story', methods=['POST', 'GET'])
@login_required
def delete_story():
    form = DeleteStoryForm()
    if form.validate_on_submit():
        Story.query.filter(Story.id == form.story_id.data, Story.user_id == current_user.id).delete()
        db.session.commit()
        return redirect(url_for('my_story'))
    return render_template('delete_story.html', form=form)


@app.route('/my_story')
@login_required
def my_story():
    story_data = User.query.filter_by(email=current_user.email).first()
    data = []
    for i in story_data.stories:
        data.append(i)
    return render_template('readstory.html', data=data)


@app.route('/read_story')
@login_required
def read_story():
    story_data = db.session.query(User.username, Story.story).filter(User.id == Story.user_id).all()
    return render_template('readstory.html', data=story_data)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/download')
def download_file():
	path = "Resume.pdf"
	return send_file(path, as_attachment=True)
