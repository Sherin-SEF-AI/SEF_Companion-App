# SEF_Companion-App
Python GUI application for Companion_App


# SEF Companion App

The SEF Companion App is a safety application designed to provide users with real-time incident reporting, emergency alerts, location tracking, and various other safety features. This application is built using Python, Flask, SQLAlchemy, PyQt5, and integrates with the Twilio API for sending SMS alerts.

## Features

- **Real-time Incident Reporting**: Report incidents with descriptions, location, and optional images.
- **Emergency Alerts**: Send and receive emergency alerts with the press of a panic button.
- **Location Tracking**: Update and fetch the current location of the user.
- **Safe Route Recommendations**: Get safe route recommendations between two points.
- **Crowdsourced Safety Information**: Access anonymously reported safety information.
- **Multilingual Support**: Change the application language.
- **User Verification**: Verify user accounts.
- **Trusted Contacts**: Add and manage trusted contacts to receive emergency alerts.

## Requirements

- Python 3.6+
- Flask
- Flask-SQLAlchemy
- Flask-JWT-Extended
- Flask-Migrate
- Flask-SocketIO
- Flask-CORS
- SQLAlchemy
- PyQt5
- Requests
- Geopy
- Twilio

## Installation

1. **Clone the repository**

   ```sh
   git clone https://github.com/Sherin-SEF-AI/SEF_Companion-App.git
   cd SEF_Companion-App


Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

Initialize the database
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

Run the backend server
python app.py

Run the PyQt5 frontend

python main.py


Twilio Configuration: Update your Twilio credentials in app.py

TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
TWILIO_PHONE_NUMBER = 'your_twilio_phone_number'

