from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
from geopy.geocoders import Nominatim
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from twilio.rest import Client

# Twilio credentials
TWILIO_ACCOUNT_SID = 'AC9221586ccf5d4c99cc8601a36f122657'
TWILIO_AUTH_TOKEN = '622161923ca8ccbea13a5a356a4fbecc'
TWILIO_PHONE_NUMBER = '+12319036694'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sef.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    country_code = db.Column(db.String(5), nullable=False)
    verified = db.Column(db.Boolean, default=False)

class TrustedContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    country_code = db.Column(db.String(5), nullable=False)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Allow null for anonymous reports
    description = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    anonymous = db.Column(db.Boolean, default=False)
    image_path = db.Column(db.String(200), nullable=True)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class EmergencyAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'], password=data['password'],
                    phone_number=data['phone_number'], country_code=data['country_code'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.password == data['password']:
        access_token = create_access_token(identity={'username': user.username, 'email': user.email})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/verify', methods=['POST'])
@jwt_required()
def verify_user():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    user.verified = True
    db.session.commit()
    return jsonify({"message": "User verified successfully"}), 200

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username, 'email': user.email} for user in users])

@app.route('/report_incident', methods=['POST'])
@jwt_required(optional=True)
def report_incident():
    current_user = get_jwt_identity()
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
    else:
        file_path = None

    data = request.form.to_dict()
    if current_user:
        user = User.query.filter_by(email=current_user['email']).first()
        user_id = user.id
        anonymous = False
    else:
        user_id = None
        anonymous = True
    new_incident = Incident(user_id=user_id, description=data['description'],
                            latitude=float(data['latitude']), longitude=float(data['longitude']),
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            anonymous=anonymous, image_path=file_path)
    db.session.add(new_incident)
    db.session.commit()
    socketio.emit('new_incident', {'description': data['description'], 'latitude': data['latitude'], 'longitude': data['longitude'], 'timestamp': data['timestamp']})
    return jsonify({"message": "Incident reported successfully"}), 201

@app.route('/incidents', methods=['GET'])
@jwt_required()
def get_incidents():
    incidents = Incident.query.all()
    return jsonify([{'user_id': incident.user_id, 'description': incident.description,
                     'latitude': incident.latitude, 'longitude': incident.longitude,
                     'timestamp': incident.timestamp.isoformat(), 'anonymous': incident.anonymous, 'image_path': incident.image_path} for incident in incidents])

@app.route('/feedback', methods=['POST'])
@jwt_required()
def submit_feedback():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    data = request.get_json()
    new_feedback = Feedback(user_id=user.id, comments=data['comments'], 
                            timestamp=datetime.fromisoformat(data['timestamp']),
                            latitude=data.get('latitude'), longitude=data.get('longitude'))
    db.session.add(new_feedback)
    db.session.commit()
    return jsonify({"message": "Feedback submitted successfully"}), 201

@app.route('/feedback', methods=['GET'])
@jwt_required()
def get_feedback():
    feedbacks = Feedback.query.all()
    return jsonify([{'user_id': feedback.user_id, 'comments': feedback.comments,
                     'latitude': feedback.latitude, 'longitude': feedback.longitude,
                     'timestamp': feedback.timestamp.isoformat()} for feedback in feedbacks])

@app.route('/update_location', methods=['POST'])
@jwt_required()
def update_location():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    data = request.get_json()
    new_location = Location(user_id=user.id, latitude=data['latitude'], longitude=data['longitude'], timestamp=datetime.utcnow())
    db.session.add(new_location)
    db.session.commit()
    return jsonify({"message": "Location updated successfully"}), 201

@app.route('/nearby_incidents', methods=['POST'])
@jwt_required()
def nearby_incidents():
    data = request.get_json()
    latitude = data['latitude']
    longitude = data['longitude']
    radius = data['radius']
    
    incidents = Incident.query.filter(
        Incident.latitude.between(latitude - radius, latitude + radius),
        Incident.longitude.between(longitude - radius, longitude + radius)
    ).all()
    
    return jsonify([{'user_id': incident.user_id, 'description': incident.description,
                     'latitude': incident.latitude, 'longitude': incident.longitude,
                     'timestamp': incident.timestamp.isoformat(), 'anonymous': incident.anonymous, 'image_path': incident.image_path} for incident in incidents])

@app.route('/panic_button', methods=['POST'])
@jwt_required()
def panic_button():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    new_alert = EmergencyAlert(user_id=user.id, message="Panic button pressed!", timestamp=datetime.utcnow())
    db.session.add(new_alert)
    db.session.commit()
    socketio.emit('emergency_alert', {'message': "Panic button pressed!", 'user_id': user.id, 'timestamp': new_alert.timestamp.isoformat()})
    
    # Send SMS to trusted contacts
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    contacts = TrustedContact.query.filter_by(user_id=user.id).all()
    for contact in contacts:
        client.messages.create(
            body=f"Panic button pressed by {user.username}.",
            from_=TWILIO_PHONE_NUMBER,
            to=f"{contact.country_code}{contact.phone_number}"
        )
    
    return jsonify({"message": "Panic button alert sent"}), 201

@app.route('/emergency_alerts', methods=['GET'])
@jwt_required()
def get_emergency_alerts():
    alerts = EmergencyAlert.query.all()
    return jsonify([{'user_id': alert.user_id, 'message': alert.message, 'timestamp': alert.timestamp.isoformat()} for alert in alerts])

@app.route('/safe_route', methods=['POST'])
def safe_route():
    data = request.get_json()
    origin = data['origin']
    destination = data['destination']
    # This is a placeholder implementation. Replace with actual safe route logic using a mapping service.
    route = {
        "origin": origin,
        "destination": destination,
        "route": [
            {"lat": origin[0], "lon": origin[1]},
            {"lat": destination[0], "lon": destination[1]}
        ],
        "safety_score": 8.5
    }
    return jsonify(route), 200

@app.route('/crowdsourced_data', methods=['GET'])
def get_crowdsourced_data():
    incidents = Incident.query.filter_by(anonymous=True).all()
    return jsonify([{'description': incident.description, 'latitude': incident.latitude,
                     'longitude': incident.longitude, 'timestamp': incident.timestamp.isoformat()} for incident in incidents])

@app.route('/trusted_contacts', methods=['POST'])
@jwt_required()
def add_trusted_contact():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    data = request.get_json()
    new_contact = TrustedContact(user_id=user.id, name=data['name'], phone_number=data['phone_number'], country_code=data['country_code'])
    db.session.add(new_contact)
    db.session.commit()
    return jsonify({"message": "Trusted contact added successfully"}), 201

@app.route('/trusted_contacts', methods=['GET'])
@jwt_required()
def get_trusted_contacts():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    contacts = TrustedContact.query.filter_by(user_id=user.id).all()
    return jsonify([{'name': contact.name, 'phone_number': contact.phone_number, 'country_code': contact.country_code} for contact in contacts])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)
