from ast import literal_eval
import json
import os
import hmac
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Configurazione del database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Newevents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
migrate = Migrate(app, db)
def hmac_sha256(key, s):
    return hmac.new(key.encode('utf-8'), s.encode('utf-8'), 'sha256').hexdigest()

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    settings = db.relationship('ButtonSettings', backref='user', uselist=False)

    def __init__(self, email, password, username):
        self.email = email
        self.password = self.set_password(password)
        self.username = username

    def set_password(self, password):
        return generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.secret_key, expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.secret_key)
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class ButtonSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    num_buttons = db.Column(db.Integer, nullable=False)
    button_labels = db.Column(db.JSON, nullable=False)
    button_states = db.Column(db.String, nullable=False)  # Aggiunto campo per lo stato dei pulsanti
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
   
    def erainti(self, button_name, state, username):
        self.num_buttons = num_buttons
        self.button_states = button_states
        self.user_id = user_id 
    def __init__(self, num_buttons, button_labels, button_states, user_id):
        self.num_buttons = num_buttons
        self.button_labels = button_labels
        self.button_states = button_states
        self.user_id = user_id        

    def __repr__(self):
        return f'<ButtonSettings for {self.user.username}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
with app.app_context():
    db.create_all()


# Forms
class RegistrationForm(FlaskForm):
    
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    
    submit = SubmitField('Register')

    def validate_email(self, email):
        print("password.data 93 ",self.password.data)
        print("confirm_password.data 94 ",self.confirm_password.data)
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    '''if 'email' in session:
        print("105 ")
        return redirect(url_for('dashboard'))'''
    if form.validate_on_submit():
        print("108 ")
        email = form.email.data
        password = form.password.data
        username = form.username.data
        print(" in regi password",password)
        if register_user(email, password, username):
            session['email'] = email
            body = "Thank you for registering!"
            #send_registration_email(email, body)
            return redirect(url_for('login'))
        else:
            flash("User already exists.")
            print("User already exists.")
    return render_template('DBregister.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print("142")
        print("password ",password)
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['email'] = email
            print("153  verifacto")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('DBlogin.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print("155")
        if user:
            token = user.get_reset_token()
            body = f"To reset your password, visit the following link: {url_for('reset_token', token=token, _external=True)}"
            #send_registration_email(form.email.data, body)
            flash('An email has been sent with instructions to reset your password.', 'info')
            print("155")
            print(body)
            return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

def register_user(email, password, username):
    if User.query.filter_by(email=email).first():
        return False
    new_user = User(email=email, password=generate_password_hash(password), username=username)
    db.session.add(new_user)
    db.session.commit()
    return True
 
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    print("196")
    if 'email' not in session:
        print("183")
        return redirect(url_for('login'))
    if request.method == 'POST':
        print("186")
        num_buttons = request.form['num_buttons']
        button_labels = [request.form.get(f'button{i+1}') for i in range(int(num_buttons))]
        # Handle saving button settings logic
        print("email",session['email'])
        print("num_buttons",num_buttons)
        print("button_labels",button_labels)
        return render_template('DBdashboard.html', email=session['email'])
    return render_template('DBdashboard.html', email=session['email'])
############################################inizia ############################ il tuo progetto 
@app.route("/", methods=["GET", "POST"])
def home():
    print("210")
    if "email" in session:
        return redirect("/dashboard")
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if login_user(email, password):
            session["email"] = email
            return redirect("/dashboard")
        else:
            return render_template("login.html", error="Invalid email or password.")
    return redirect(url_for('login'))
'''
@app.route('/toggle', methods=['GET', 'POST'])
@login_required
def toggle():
    if 'email' not in session:
        flash('You are not logged in. Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()

    if request.method == 'POST':
        num_buttons = int(request.form['num_buttons'])
        print(" num_buttons 255 ",num_buttons)
        button_labels = [request.form[f'button{i+1}'] for i in range(num_buttons)]
        button_states = ['off'] * num_buttons  # Impostare tutti i pulsanti su 'off' inizialmente

        # Salva o aggiorna le impostazioni dei pulsanti nel database
      
        if button_settings:
            button_settings.num_buttons = num_buttons
            button_settings.button_labels = json.dumps(button_labels)
            button_settings.button_states = json.dumps(button_states)
        else:
            new_button_settings = ButtonSettings(
                num_buttons=num_buttons,
                button_labels=json.dumps(button_labels),
                button_states=json.dumps(button_states),
                user_id=user.id
            )
            db.session.add(new_button_settings)
        

        db.session.commit()
         # Passa i dati necessari al template Jinja
        button_labels = json.loads(button_settings.button_labels)
        button_states = json.loads(button_settings.button_states)
        print("num_buttons 318 : ",num_buttons)
        print("button_labels ",button_labels)
        print("button_states  : ",button_states)
        
        print("num_buttons 322 type( : ",type(num_buttons))
        print("button_labels type( ",type(button_labels))
        print("button_states  type( : ",type(button_states))
        return render_template('toggle.html', num_buttons=num_buttons, button_labels=button_labels,
                               button_states=button_states)
    else:
        if button_settings:
            button_labels = json.loads(button_settings.button_labels)
            button_states = json.loads(button_settings.button_states)
            print("button_settings.num_buttons 329 : ",button_settings.num_buttons)
            print("button_settings.button_labels ",button_settings.button_labels)
            print("button_settings.button_states  : ",button_settings.button_states)
            return render_template('toggle.html', num_buttons=button_settings.num_buttons,
                                   button_labels=button_settings.button_labels,
                                   button_states=button_settings.button_states)
        else:
            return render_template('toggle.html', num_buttons=1, button_labels=[], button_states=[])
'''
@app.route('/toggle', methods=['GET', 'POST'])
@login_required
def toggle():
    if 'email' not in session:
        flash('You are not logged in. Please log in to access this page.', 'danger')
        return redirect(url_for('login'))    
    user = User.query.filter_by(email=session['email']).first()
    button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()

    if request.method == 'POST':
        num_buttons = int(request.form['num_buttons'])
        button_labels = [request.form[f'button{i+1}'] for i in range(num_buttons)]
        button_states = ['off'] * num_buttons

        if button_settings:
            button_settings.num_buttons = num_buttons
            button_settings.button_labels = json.dumps(button_labels)
            button_settings.button_states = json.dumps(button_states)
        else:
            new_button_settings = ButtonSettings(
                num_buttons=num_buttons,
                button_labels=json.dumps(button_labels),
                button_states=json.dumps(button_states),
                user_id=user.id
            )
            db.session.add(new_button_settings)
        db.session.commit()

    if button_settings:
        num_buttons = button_settings.num_buttons
        button_labels = json.loads(button_settings.button_labels)
        button_states = json.loads(button_settings.button_states)
    else:
        num_buttons = 0
        button_labels = []
        button_states = []

    return render_template('toggle.html', num_buttons=num_buttons, button_labels=button_labels, button_states=button_states)


@app.route('/state', methods=['POST'])
@login_required
def update_state():
    print("359")
    # Recupera l'utente corrente
    user = current_user

    # Recupera le impostazioni del pulsante per l'utente corrente
    button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
    print("button_settings.button_states 374 ",button_settings.button_states)
    print("type(button_settings.button_states) 375 ", type(button_settings.button_states))
    if not button_settings:
        return jsonify({'error': 'Button settings not found for the current user.'}), 404
    # Ottieni i dati JSON dalla richiesta
    data = request.get_json()
    button_id = int(data.get('buttonId'))
    new_state = data.get('state')
    button_label = data.get('buttonLabel')
    print("---Line 108 ---------data from esp32 /state-------button_id---------")
    print(button_id)
    print("-@@@@@@@@@@--data from esp32 /state-------button_label---------")
    print(button_label)
    print("button_settings.button_states[button_id] 389 ",button_settings.button_states[button_id])    
    print("-----------fine /state ---data from esp32 ----------------")
    # Aggiorna lo stato del pulsante nel database
    #button_settings.button_states[button_id] = "new_state"
    print("393")
    print(type(new_state))
    print("Updated button_states:393 ", button_settings.button_states)
    print("Updated button_labels:", button_settings.button_labels)
    
        # Ensure button_states is a list or dictionary
    button_states = literal_eval(button_settings.button_states)
    button_states[button_id] = new_state
    button_settings.button_states = str(button_states)

    db.session.commit()    
    

    print(" 408     DOPO UPDATE ")
    button_settings = ButtonSettings.query.filter_by(user_id=user.id).first()
    print("Updated button_states:420", button_settings.button_states)
    print("Updated button_labels:", button_settings.button_labels)

    # Passa i dati necessari al template Jinja
    num_buttons = len(button_settings.button_labels)  # Numero dei pulsanti
    button_labels = button_settings.button_labels  # Etichette dei pulsanti
    button_states = button_settings.button_states  # Stati dei pulsanti
    print("button_id 386 : ",button_id)
    print("new_state ",new_state)
    print("button_states ",button_states)
    print("button_label  : ",button_label)
    # Supponendo che button_data sia già preparato correttamente altrove nel codice
    #button_data = [...]  # Dati dei pulsanti

    # Esempio di come potresti passare i dati al template
    #return render_template('toggle.html', num_buttons=num_buttons, button_labels=button_labels, button_states=button_states, button_data=button_data)
    return jsonify({'message': f'State updated for button {button_label}'})

@app.route('/Pstate', methods=['GET', 'POST'])
@login_required
def Pupdate_state():
    global aved_button_id, aved_button_label, Sbutton_data, button_data
    global rin, saved_button_Pin

    user = current_user
    settings = user.settings
    
    if settings:
        saved_button_Pin = [2] * settings.num_buttons
        print("548 settings.num_buttons  ", settings.num_buttons)
        saved_button_labels = settings.button_labels
        saved_button_states = settings.button_states
        num_buttons = settings.num_buttons
    else:
        saved_button_Pin = []
        saved_button_labels = []
        saved_button_states = []
        num_buttons = 0  # Add this line to handle the case where settings is None

    Sbutton_data = []
    if request.method == 'POST':
        data = request.get_json()
        button_id = int(data.get('buttonId'))
        buttonPin = data.get('buttonPin')
        print("-line 134 ----------data from esp32 /state-------buttonPin---------")
        print(buttonPin)
        button_label = data.get('buttonLabel')

        print("Line 166 saved_button_PIN prima")
        print(saved_button_Pin)
        print(f"Line 168 len(saved_button_PIN) prima", len(saved_button_Pin))
        print(len(saved_button_Pin))
        print(f"num_buttons:", num_buttons)

        for rin in range(num_buttons):
            print("Line 172 buttonPin dentro if ")
            print(f"buttonPin::", buttonPin)
            print(f"rin:", rin)
            saved_button_Pin[rin] = buttonPin
        
        print("Line 169 saved_button_PIN   dopo ")
        print(saved_button_Pin)
        aved_button_id = button_id
        aved_button_label = button_label

        print("------POST----data from esp32 /Pstate-------button_id---------")
        print(button_id)
        print("-line 134 ----------data from esp32 /state-------buttonPin---------")
        print(buttonPin)
        print("---line 135 ######## POST ###--data from esp32 /Pstate-------button_label---------")
        print(button_label)
        print("---Line 138 ---------data from esp32 /Pstate----------------")
        print(data)
        print("-----------fine /Pstate ---data from esp32 ----------------")
        Sbutton_data = [{'buttonId': button_id, 'buttonLabel': button_label}]
        print("-line 141-------button data  dentro---------------------")
        print("#####  Line 142 ############   button_data   type  ######################")
        print(type(Sbutton_data))
        print(Sbutton_data)
        aved_button_id = button_id
        aved_button_label = button_label

        print("Line 157 saved_button_PIN")
        print(saved_button_Pin)
        print("Line 158 saved_button_labels")
        print(aved_button_label)
        session['button_id'] = button_id
        session['button_label'] = button_label
        print("lINE 150 session['button_label']")
        print(session['button_label'])

        return render_template('hity.html', button_data=Sbutton_data)

    # Handle GET request
    if not Sbutton_data:
        print("#line 151  impongo  Sbutton_data valori default   fuori Sbutton data#############")
        print(Sbutton_data)
        
        button_id = session.get('button_id')
        button_label = session.get('button_label')
        print("Line 165session.get('button_id')")
        print(session.get('button_id'))
        Sbutton_data = [{'buttonId': button_id, 'buttonLabel': button_label}]
        print("#line 155   Sbutton_data DOPO  fuori Sbutton data#############")
        print(Sbutton_data)
    
    # Ensure `aved_button_id` and `aved_button_label` have default values
    aved_button_id = aved_button_id if 'aved_button_id' in globals() else 0
    aved_button_label = aved_button_label if 'aved_button_label' in globals() else 'default'
    
    button_id = aved_button_id
    button_label = aved_button_label
    button_data = [{'buttonId': button_id, 'buttonLabel': button_label}]

    print("Line 182 saved_button_Pin")
    print(saved_button_Pin)
    print("Line 184 saved_button_labels")
    print(saved_button_labels)
    print("type(saved_button_labels) 512 ",type(saved_button_labels))

    result = []
    resultp = []

    for i in range(len(saved_button_Pin)):
        button_id = saved_button_Pin[i]
        #button_label = saved_button_labels[i]
        #button_label = saved_button_labels.split(", ")[i]
        #####button_label = saved_button_labels.strip("[]").split(", ")[i]
        button_label = saved_button_labels.strip("[]").split(", ")[i].strip('"')
        resultp.append( button_label)
        result.append({'buttonId': button_id, 'buttonLabel': button_label})
        print(" lINE  204  --result---:")

    print(result) 
    print(resultp) 
    print(type(resultp))
    print(" lINE  209  --result-TYPE--:")

    print(type(result))

    # Ensure that button_index is within the valid range
    button_index = 0
    if len(saved_button_labels) > 0:
        button_index = len(saved_button_labels) - 1
    print("#line 198  ##################     fuori Sbutton data####################")
    print(button_data)
    
    #return render_template('toggle.html', num_buttons=num_buttons, button_labels=saved_button_labels,
                           #button_states=saved_button_states, button_data=result)
    return render_template('toggle.html', num_buttons=num_buttons, button_labels= resultp,button_states=saved_button_states, button_data=result)

if __name__ == '__main__':
   
    app.run(port=50380, debug=True)
