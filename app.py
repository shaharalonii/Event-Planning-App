from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_migrate import Migrate
import secrets
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp
from datetime import date
import random

app = Flask(__name__, static_folder='static')

app.secret_key = secrets.token_hex(16)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True


db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, max=16),
        Regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,16}$',
               message='Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Reset Password')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, max=16),
        Regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,16}$',
               message='Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number.')
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=16),
        Regexp(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,16}$',
               message='Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    privacy_preference = StringField('Privacy Preference')
    submit = SubmitField('Register')

class SettingsForm(FlaskForm):
    privacy_preference = StringField('Privacy Preference')
    contact = StringField('Contact')
    submit = SubmitField('Save Changes')


class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    privacy_preference = db.Column(db.String(20))
    contact = db.Column(db.String(100))
    event_preferences = db.Column(db.Text)
    profile_picture = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=False)
    reset_token = db.Column(db.String(100))

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date)
    privacy_preference = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('events', lazy=True))
    deleted = db.Column(db.Boolean, default=False)  # Add this line

    def __repr__(self):
        return f"Event('{self.title}', '{self.date}')"

with app.app_context():
    db.create_all()

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data

        if bcrypt.check_password_hash(current_user.password, current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('settings'))
        else:
            flash('Current password is incorrect', 'danger')

    return render_template('change_password.html', form=form)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()  # Create a form for user settings
    
    if form.validate_on_submit():
        # Update the user's settings based on the form data
        current_user.privacy_preference = form.privacy_preference.data
        current_user.contact = form.contact.data
        # ... update other user settings ...
        db.session.commit()
        flash('Settings updated successfully', 'success')
        return redirect(url_for('settings'))
    
    # Pre-populate the form with the user's current settings
    form.privacy_preference.data = current_user.privacy_preference
    form.contact.data = current_user.contact
    # ... populate other form fields with user settings ...
    
    return render_template('settings.html', form=form)

@app.route('/events/<int:event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id == current_user.id:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully', 'success')
        return jsonify({'message': 'Event deleted successfully'})
    flash('You are not authorized to delete this event', 'danger')
    return jsonify({'message': 'Unauthorized'})

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date = request.form.get('date')
        event = Event(title=title, description=description, date=date, user_id=None)
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully', 'success')
        return redirect(url_for('home'))

    events = Event.query.filter_by(privacy_preference='public').all()
    return render_template('home.html', events=events)

@app.route('/public_events')
def public_events():
    public_upcoming_events = Event.query.join(User).filter(Event.date >= date.today(), User.privacy_preference == 'public', Event.deleted == False).all()
    random.shuffle(public_upcoming_events)
    events = public_upcoming_events[:10]
    return render_template('public_events.html', events=events)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        privacy_preference = form.privacy_preference.data
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))
        user = User(name=name, email=email, password=password, privacy_preference=privacy_preference)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    user = current_user
    # Perform the deletion logic here, such as deleting user-related data from the database
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            user.is_active = True
            db.session.commit()
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.')
    return render_template('login.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You are not authorized to edit this event', 'danger')
        return redirect(url_for('dashboard'))

    form = EventForm(obj=event)

    if form.validate_on_submit():
        event.title = form.title.data
        event.description = form.description.data
        event.date = form.date.data
        db.session.commit()
        flash('Event updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_event.html', form=form, event=event)


@app.route('/update_event/<int:event_id>', methods=['POST'])
@login_required
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    form = EventForm()

    if form.validate_on_submit():
        event.title = form.title.data
        event.date = form.date.data
        db.session.commit()
        flash('Event updated successfully', 'success')
        return redirect(url_for('home'))

    return render_template('edit_event.html', form=form, event=event)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    form = EventForm()
    if form.validate_on_submit():
        event = Event(
            title=form.title.data,
            description=form.description.data,
            date=form.date.data,
            user=current_user
        )
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_event.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    past_events = Event.query.filter(Event.date < date.today(), Event.user_id == current_user.id).order_by(
        Event.date.desc()).all()
    future_events = Event.query.filter(Event.date >= date.today(), Event.user_id == current_user.id).order_by(
        Event.date).all()
    upcoming_events = Event.query.filter(Event.date >= date.today(), Event.user_id == current_user.id).order_by(
        Event.date).all()
    form = EventForm()
    return render_template('dashboard.html', past_events=past_events, future_events=future_events,
                           upcoming_events=upcoming_events, form=form)

def generate_reset_token(user_id):
    token = secrets.token_hex(16)
    user = User.query.get(user_id)
    user.reset_token = token
    db.session.commit()
    reset_url = url_for('reset_password_action', reset_token=token, _external=True)
    return reset_url

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        reset_token = secrets.token_hex(16)
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            user.reset_token = reset_token
            db.session.commit()
        return redirect(url_for('reset_password_action', reset_token=reset_token))
    return render_template('forgot_password.html')

@app.route('/reset_password/<reset_token>', methods=['GET', 'POST'])
def reset_password_action(reset_token):
    user = User.query.filter_by(reset_token=reset_token).first()
    if not user:
        flash('Invalid or expired reset token. Please try again.', 'danger')
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = password
        user.reset_token = None
        db.session.commit()
        flash('Password reset successful. You can now log in with your new password.', 'success')
        return redirect(url_for('password_reset_success'))
    return render_template('reset_password.html', form=form, reset_token=reset_token)

@app.route('/password_reset_success')
def password_reset_success():
    return render_template('password_reset_success.html')

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')


if __name__ == '__main__':
    app.run(debug=True)
