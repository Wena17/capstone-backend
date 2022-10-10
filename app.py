from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import dotenv
import datetime
from flask_login import LoginManager
from .forms import SignupForm, LoginForm

dotenv.load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{dbuser}:{dbpass}@{dbhost}/{dbname}'.format(
    dbuser=os.environ['DBUSER'],
    dbpass=os.environ['DBPASS'],
    dbhost=os.environ['DBHOST'],
    dbname=os.environ['DBNAME']
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.get(id)

# Device message types
JOIN_ACCEPT = 1

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Login route logic goes here


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    User sign-up page.

    GET requests serve sign-up page.
    POST requests validate form & user creation.
    """
    form = SignupForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user is None:
            user = User(
                name=form.name.data,
                email=form.email.data,
                website=form.website.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()  # Create new user
            login_user(user)  # Log in as newly created user
            return redirect("/")
        flash('A user already exists with that email address.')
    return render_template(
        'signup.html',
        title='Create an Account.',
        form=form,
        template='signup-page',
        body="Sign up for a user account."
    )
    
@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/health")
def health_check():
    return "I'm fine"

@app.route('/messages')
def show_messages():
    msgs = DeviceMessage.query.order_by(DeviceMessage.ts).all()
    return render_template('messages.html', messages=msgs)

@app.route('/devices')
def show_devices():
    data = Device.query.order_by(Device.ts).all()
    return render_template('devices.html', devices=data)

@app.route('/devices/<string:dev_id>')
def show_device(dev_id):
    dev = Device.query.filter_by(dev_id=dev_id).first()
    return render_template('device.html', dev=dev)

@app.route('/registration/<string:dev_id>')
def show_registration(dev_id):
    return render_template('registration.html', dev_id=dev_id)

# IoT API

@app.route("/api/v1/register-device", methods=["POST"])
def register_device():
    data = request.json
    dev = Device(dev_id=data["dev_id"], lat=data["lat"], long=data["long"])
    db.session.add(dev)
    db.session.commit()
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/uplinkMessage", methods=['POST'])
def uplinkMessage():
    msg = request.json
    print(f"---> Received uplink message: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/normalizedUplink", methods=['POST'])
def normalizedUplink():
    msg = request.json
    print(f"---> Received normalized uplink: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/joinAccept", methods=['POST'])
def joinAccept():
    msg = request.json
    # TODO: Only accept join requests from previouslz registered devices
    print(f"---> Received join accept: {msg}")
    if msg["end_device_ids"]["application_ids"]["application_id"] != "wena-util-moni":
        return ("Wrong application ID", 403)
    else:
        dev_msg = DeviceMessage()
        dev_msg.dev_id = msg["end_device_ids"]["device_id"]
        dev_msg.msg_type = JOIN_ACCEPT
        db.session.add(dev_msg)
        db.session.commit()
    resp = jsonify(success=True) # { "success": true }
    return resp

@app.route("/api/v1/iot/locationSolved", methods=['POST'])
def locationSolved():
    msg = request.json
    print(f"---> Received location solved: {msg}")
    resp = jsonify(success=True) # { "success": true }
    return resp

# Data model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    email = db.Column(
        db.String(40),
        unique=True,
        nullable=False
    )
    password = db.Column(
        db.String(200),
        primary_key=False,
        unique=False,
        nullable=False
	)
    created_on = db.Column(
        db.DateTime,
        index=False,
        unique=False,
        nullable=True
    )
    last_login = db.Column(
        db.DateTime,
        index=False,
        unique=False,
        nullable=True
    )

    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(
            password,
            method='sha256'
        )

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_id = db.Column(db.String(32), index=True, nullable=False, unique=True)
    lat = db.Column(db.Float)
    long = db.Column(db.Float)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)

class DeviceMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dev_id = db.Column(db.String(32), index=True, nullable=False)
    msg_type = db.Column(db.Integer)
    ts = db.Column(db.DateTime, default=datetime.datetime.now)

    def msg_type_name(self):
        if self.msg_type is None:
            return "No message type"
        else:
            names = ['Unknown Message', 'Join Accept']
            return names[self.msg_type]
