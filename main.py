import sys
import requests
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
                             QMessageBox, QListWidget, QDateTimeEdit, QTextEdit, QTabWidget, QComboBox, QFileDialog)
from PyQt5.QtCore import QDateTime, Qt
from datetime import datetime
from PyQt5.QtCore import QTranslator, QLocale

class SEFCompanionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.jwt_token = None
    
    def initUI(self):
        self.setWindowTitle('SEF Companion App')
        self.setGeometry(100, 100, 800, 600)
    
        self.tabs = QTabWidget()
    
        self.loginTab = QWidget()
        self.registerTab = QWidget()
        self.userTab = QWidget()
        self.incidentTab = QWidget()
        self.feedbackTab = QWidget()
        self.locationTab = QWidget()
        self.safetyTab = QWidget()
    
        self.tabs.addTab(self.loginTab, "Login")
        self.tabs.addTab(self.registerTab, "Register")
        self.tabs.addTab(self.userTab, "Users")
        self.tabs.addTab(self.incidentTab, "Incidents")
        self.tabs.addTab(self.feedbackTab, "Feedback")
        self.tabs.addTab(self.locationTab, "Location & Alerts")
        self.tabs.addTab(self.safetyTab, "Safety")
    
        self.initLoginTab()
        self.initRegisterTab()
        self.initUserTab()
        self.initIncidentTab()
        self.initFeedbackTab()
        self.initLocationTab()
        self.initSafetyTab()
    
        mainLayout = QVBoxLayout()
        mainLayout.addWidget(self.tabs)
    
        self.setLayout(mainLayout)
    
    def initLoginTab(self):
        layout = QVBoxLayout()
    
        self.loginEmailLabel = QLabel('Email:', self)
        self.loginEmailInput = QLineEdit(self)
    
        self.loginPasswordLabel = QLabel('Password:', self)
        self.loginPasswordInput = QLineEdit(self)
        self.loginPasswordInput.setEchoMode(QLineEdit.Password)
    
        self.loginButton = QPushButton('Login', self)
        self.loginButton.clicked.connect(self.login_user)
    
        layout.addWidget(self.loginEmailLabel)
        layout.addWidget(self.loginEmailInput)
        layout.addWidget(self.loginPasswordLabel)
        layout.addWidget(self.loginPasswordInput)
        layout.addWidget(self.loginButton)
    
        self.loginTab.setLayout(layout)
    
    def initRegisterTab(self):
        layout = QVBoxLayout()
    
        self.usernameLabel = QLabel('Username:', self)
        self.usernameInput = QLineEdit(self)
    
        self.emailLabel = QLabel('Email:', self)
        self.emailInput = QLineEdit(self)
    
        self.passwordLabel = QLabel('Password:', self)
        self.passwordInput = QLineEdit(self)
        self.passwordInput.setEchoMode(QLineEdit.Password)
    
        self.phoneNumberLabel = QLabel('Phone Number:', self)
        self.phoneNumberInput = QLineEdit(self)
    
        self.countryCodeLabel = QLabel('Country Code:', self)
        self.countryCodeInput = QComboBox(self)
        self.countryCodeInput.addItems(["+1", "+91", "+44", "+61", "+81"])  # Add more country codes as needed
    
        self.registerButton = QPushButton('Register', self)
        self.registerButton.clicked.connect(self.register_user)
    
        layout.addWidget(self.usernameLabel)
        layout.addWidget(self.usernameInput)
        layout.addWidget(self.emailLabel)
        layout.addWidget(self.emailInput)
        layout.addWidget(self.passwordLabel)
        layout.addWidget(self.passwordInput)
        layout.addWidget(self.phoneNumberLabel)
        layout.addWidget(self.phoneNumberInput)
        layout.addWidget(self.countryCodeLabel)
        layout.addWidget(self.countryCodeInput)
        layout.addWidget(self.registerButton)
    
        self.registerTab.setLayout(layout)
    
    def initUserTab(self):
        layout = QVBoxLayout()
    
        self.fetchUsersButton = QPushButton('Fetch Users', self)
        self.fetchUsersButton.clicked.connect(self.fetch_users)
    
        self.userList = QListWidget(self)
    
        layout.addWidget(self.fetchUsersButton)
        layout.addWidget(self.userList)
    
        self.userTab.setLayout(layout)
    
    def initIncidentTab(self):
        layout = QVBoxLayout()
    
        self.incidentDescriptionLabel = QLabel('Incident Description:', self)
        self.incidentDescriptionInput = QTextEdit(self)
    
        self.incidentTimeLabel = QLabel('Incident Time:', self)
        self.incidentTimeInput = QDateTimeEdit(self)
        self.incidentTimeInput.setDateTime(QDateTime.currentDateTime())
    
        self.anonymousCheckBox = QComboBox(self)
        self.anonymousCheckBox.addItem('Report Anonymously')
        self.anonymousCheckBox.addItem('Report with Identity')
    
        self.imageButton = QPushButton('Upload Image', self)
        self.imageButton.clicked.connect(self.upload_image)
        self.imagePath = ""
    
        self.reportIncidentButton = QPushButton('Report Incident', self)
        self.reportIncidentButton.clicked.connect(self.report_incident)
    
        self.fetchIncidentsButton = QPushButton('Fetch Incidents', self)
        self.fetchIncidentsButton.clicked.connect(self.fetch_incidents)
    
        self.incidentList = QListWidget(self)
    
        layout.addWidget(self.incidentDescriptionLabel)
        layout.addWidget(self.incidentDescriptionInput)
        layout.addWidget(self.incidentTimeLabel)
        layout.addWidget(self.incidentTimeInput)
        layout.addWidget(self.anonymousCheckBox)
        layout.addWidget(self.imageButton)
        layout.addWidget(self.reportIncidentButton)
        layout.addWidget(self.fetchIncidentsButton)
        layout.addWidget(self.incidentList)
    
        self.incidentTab.setLayout(layout)
    
    def initFeedbackTab(self):
        layout = QVBoxLayout()
    
        self.feedbackLabel = QLabel('Feedback:', self)
        self.feedbackInput = QTextEdit(self)
    
        self.submitFeedbackButton = QPushButton('Submit Feedback', self)
        self.submitFeedbackButton.clicked.connect(self.submit_feedback)
    
        self.fetchFeedbackButton = QPushButton('Fetch Feedback', self)
        self.fetchFeedbackButton.clicked.connect(self.fetch_feedback)
    
        self.feedbackList = QListWidget(self)
    
        layout.addWidget(self.feedbackLabel)
        layout.addWidget(self.feedbackInput)
        layout.addWidget(self.submitFeedbackButton)
        layout.addWidget(self.fetchFeedbackButton)
        layout.addWidget(self.feedbackList)
    
        self.feedbackTab.setLayout(layout)
    
    def initLocationTab(self):
        layout = QVBoxLayout()
    
        self.updateLocationButton = QPushButton('Update Location', self)
        self.updateLocationButton.clicked.connect(self.update_location)
    
        self.nearbyIncidentsButton = QPushButton('Fetch Nearby Incidents', self)
        self.nearbyIncidentsButton.clicked.connect(self.fetch_nearby_incidents)
    
        self.panicButton = QPushButton('Panic Button', self)
        self.panicButton.clicked.connect(self.panic_button)
    
        self.emergencyAlertsButton = QPushButton('Fetch Emergency Alerts', self)
        self.emergencyAlertsButton.clicked.connect(self.fetch_emergency_alerts)
    
        self.locationList = QListWidget(self)
    
        layout.addWidget(self.updateLocationButton)
        layout.addWidget(self.nearbyIncidentsButton)
        layout.addWidget(self.panicButton)
        layout.addWidget(self.emergencyAlertsButton)
        layout.addWidget(self.locationList)
    
        self.locationTab.setLayout(layout)
    
    def initSafetyTab(self):
        layout = QVBoxLayout()
    
        self.safeRouteOriginLabel = QLabel('Origin:', self)
        self.safeRouteOriginInput = QLineEdit(self)
    
        self.safeRouteDestinationLabel = QLabel('Destination:', self)
        self.safeRouteDestinationInput = QLineEdit(self)
    
        self.fetchSafeRouteButton = QPushButton('Fetch Safe Route', self)
        self.fetchSafeRouteButton.clicked.connect(self.fetch_safe_route)
    
        self.safeRouteList = QListWidget(self)
    
        layout.addWidget(self.safeRouteOriginLabel)
        layout.addWidget(self.safeRouteOriginInput)
        layout.addWidget(self.safeRouteDestinationLabel)
        layout.addWidget(self.safeRouteDestinationInput)
        layout.addWidget(self.fetchSafeRouteButton)
        layout.addWidget(self.safeRouteList)
    
        self.safetyTab.setLayout(layout)
    
    def get_current_location(self):
        try:
            response = requests.get('https://ipinfo.io/json')
            data = response.json()
            location = data['loc'].split(',')
            return float(location[0]), float(location[1])
        except Exception as e:
            QMessageBox.critical(self, 'Error', 'Unable to get the current location.')
            return None, None
    
    def register_user(self):
        username = self.usernameInput.text()
        email = self.emailInput.text()
        password = self.passwordInput.text()
        phone_number = self.phoneNumberInput.text()
        country_code = self.countryCodeInput.currentText()
        if username and email and password and phone_number and country_code:
            try:
                response = requests.post('http://localhost:5000/register', json={
                    'username': username,
                    'email': email,
                    'password': password,
                    'phone_number': phone_number,
                    'country_code': country_code
                })
                if response.status_code == 201:
                    QMessageBox.information(self, 'Success', 'User registered successfully')
                    self.usernameInput.clear()
                    self.emailInput.clear()
                    self.passwordInput.clear()
                    self.phoneNumberInput.clear()
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to register user')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Input Error', 'Please provide all the required details')
    
    def login_user(self):
        email = self.loginEmailInput.text()
        password = self.loginPasswordInput.text()
        if email and password:
            try:
                response = requests.post('http://localhost:5000/login', json={'email': email, 'password': password})
                if response.status_code == 200:
                    self.jwt_token = response.json().get('access_token')
                    QMessageBox.information(self, 'Success', 'Logged in successfully')
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to log in')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Input Error', 'Please provide email and password')
    
    def fetch_users(self):
        if self.jwt_token:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.get('http://localhost:5000/users', headers=headers)
                if response.status_code == 200:
                    users = response.json()
                    self.userList.clear()
                    for user in users:
                        self.userList.addItem(f"ID: {user['id']}, Username: {user['username']}, Email: {user['email']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch users')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'You need to log in first')
    
    def upload_image(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Image Files (*.png *.jpg *.jpeg *.gif)", options=options)
        if file_path:
            self.imagePath = file_path
    
    def report_incident(self):
        description = self.incidentDescriptionInput.toPlainText()
        timestamp = self.incidentTimeInput.dateTime().toString(Qt.ISODate)
        latitude, longitude = self.get_current_location()
        if description and latitude and longitude and self.imagePath:
            headers = {'Authorization': f'Bearer {self.jwt_token}'} if self.jwt_token else {}
            anonymous = True if self.anonymousCheckBox.currentText() == 'Report Anonymously' else False
            files = {'file': open(self.imagePath, 'rb')}
            data = {
                'description': description,
                'latitude': latitude,
                'longitude': longitude,
                'timestamp': timestamp,
                'anonymous': anonymous
            }
            try:
                response = requests.post('http://localhost:5000/report_incident', files=files, data=data, headers=headers)
                if response.status_code == 201:
                    QMessageBox.information(self, 'Success', 'Incident reported successfully')
                    self.incidentDescriptionInput.clear()
                    self.incidentTimeInput.setDateTime(QDateTime.currentDateTime())
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to report incident')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Input Error', 'Please provide all the required details')
    
    def fetch_incidents(self):
        if self.jwt_token:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.get('http://localhost:5000/incidents', headers=headers)
                if response.status_code == 200:
                    incidents = response.json()
                    self.incidentList.clear()
                    for incident in incidents:
                        self.incidentList.addItem(f"User ID: {incident['user_id']}, Description: {incident['description']}, Location: ({incident['latitude']}, {incident['longitude']}), Time: {incident['timestamp']}, Anonymous: {incident['anonymous']}, Image: {incident['image_path']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch incidents')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'You need to log in first')
    
    def submit_feedback(self):
        comments = self.feedbackInput.toPlainText()
        timestamp = datetime.now().isoformat()
        latitude, longitude = self.get_current_location()
        if comments and latitude and longitude:
            headers = {'Authorization': f'Bearer {self.jwt_token}'} if self.jwt_token else {}
            try:
                response = requests.post('http://localhost:5000/feedback', json={
                    'comments': comments,
                    'timestamp': timestamp,
                    'latitude': latitude,
                    'longitude': longitude
                }, headers=headers)
                if response.status_code == 201:
                    QMessageBox.information(self, 'Success', 'Feedback submitted successfully')
                    self.feedbackInput.clear()
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to submit feedback')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Input Error', 'Please provide feedback comments')
    
    def fetch_feedback(self):
        if self.jwt_token:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.get('http://localhost:5000/feedback', headers=headers)
                if response.status_code == 200:
                    feedbacks = response.json()
                    self.feedbackList.clear()
                    for feedback in feedbacks:
                        self.feedbackList.addItem(f"User ID: {feedback['user_id']}, Comments: {feedback['comments']}, Location: ({feedback['latitude']}, {feedback['longitude']}), Time: {feedback['timestamp']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch feedback')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'You need to log in first')
    
    def update_location(self):
        latitude, longitude = self.get_current_location()
        if latitude and longitude:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.post('http://localhost:5000/update_location', json={
                    'latitude': latitude,
                    'longitude': longitude
                }, headers=headers)
                if response.status_code == 201:
                    QMessageBox.information(self, 'Success', 'Location updated successfully')
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to update location')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'Unable to get current location')
    
    def fetch_nearby_incidents(self):
        latitude, longitude = self.get_current_location()
        radius = 0.01  # Example radius, you can adjust it as needed
        if latitude and longitude:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.post('http://localhost:5000/nearby_incidents', json={
                    'latitude': latitude,
                    'longitude': longitude,
                    'radius': radius
                }, headers=headers)
                if response.status_code == 200:
                    incidents = response.json()
                    self.locationList.clear()
                    for incident in incidents:
                        self.locationList.addItem(f"User ID: {incident['user_id']}, Description: {incident['description']}, Location: ({incident['latitude']}, {incident['longitude']}), Time: {incident['timestamp']}, Anonymous: {incident['anonymous']}, Image: {incident['image_path']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch nearby incidents')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'Unable to get current location')
    
    def panic_button(self):
        headers = {'Authorization': f'Bearer {self.jwt_token}'}
        try:
            response = requests.post('http://localhost:5000/panic_button', headers=headers)
            if response.status_code == 201:
                QMessageBox.information(self, 'Success', 'Panic button alert sent')
            else:
                QMessageBox.warning(self, 'Error', 'Failed to send panic button alert')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))
    
    def fetch_emergency_alerts(self):
        if self.jwt_token:
            headers = {'Authorization': f'Bearer {self.jwt_token}'}
            try:
                response = requests.get('http://localhost:5000/emergency_alerts', headers=headers)
                if response.status_code == 200:
                    alerts = response.json()
                    self.locationList.clear()
                    for alert in alerts:
                        self.locationList.addItem(f"User ID: {alert['user_id']}, Message: {alert['message']}, Time: {alert['timestamp']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch emergency alerts')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Error', 'You need to log in first')
    
    def fetch_safe_route(self):
        origin = self.safeRouteOriginInput.text().split(',')
        destination = self.safeRouteDestinationInput.text().split(',')
        if len(origin) == 2 and len(destination) == 2:
            try:
                response = requests.post('http://localhost:5000/safe_route', json={
                    'origin': [float(origin[0]), float(origin[1])],
                    'destination': [float(destination[0]), float(destination[1])]
                })
                if response.status_code == 200:
                    route = response.json()
                    self.safeRouteList.clear()
                    self.safeRouteList.addItem(f"Origin: {route['origin']}, Destination: {route['destination']}")
                    for point in route['route']:
                        self.safeRouteList.addItem(f"Lat: {point['lat']}, Lon: {point['lon']}")
                    self.safeRouteList.addItem(f"Safety Score: {route['safety_score']}")
                else:
                    QMessageBox.warning(self, 'Error', 'Failed to fetch safe route')
            except Exception as e:
                QMessageBox.critical(self, 'Error', str(e))
        else:
            QMessageBox.warning(self, 'Input Error', 'Please provide valid origin and destination coordinates')
    
    def change_language(self, lang):
        translator = QTranslator()
        if lang == "French":
            translator.load("fr.qm")
        elif lang == "Spanish":
            translator.load("es.qm")
        else:
            translator.load("")
        app.installTranslator(translator)
        self.retranslateUi()
    
    def retranslateUi(self):
        self.setWindowTitle(self.tr("SEF Companion App"))
        self.usernameLabel.setText(self.tr("Username:"))
        self.emailLabel.setText(self.tr("Email:"))
        self.passwordLabel.setText(self.tr("Password:"))
        self.registerButton.setText(self.tr("Register"))
        self.loginButton.setText(self.tr("Login"))
        self.fetchUsersButton.setText(self.tr("Fetch Users"))
        self.incidentDescriptionLabel.setText(self.tr("Incident Description:"))
        self.incidentTimeLabel.setText(self.tr("Incident Time:"))
        self.anonymousCheckBox.setItemText(0, self.tr("Report Anonymously"))
        self.anonymousCheckBox.setItemText(1, self.tr("Report with Identity"))
        self.reportIncidentButton.setText(self.tr("Report Incident"))
        self.fetchIncidentsButton.setText(self.tr("Fetch Incidents"))
        self.feedbackLabel.setText(self.tr("Feedback:"))
        self.submitFeedbackButton.setText(self.tr("Submit Feedback"))
        self.fetchFeedbackButton.setText(self.tr("Fetch Feedback"))
        self.updateLocationButton.setText(self.tr("Update Location"))
        self.nearbyIncidentsButton.setText(self.tr("Fetch Nearby Incidents"))
        self.panicButton.setText(self.tr("Panic Button"))
        self.emergencyAlertsButton.setText(self.tr("Fetch Emergency Alerts"))
        self.safeRouteOriginLabel.setText(self.tr("Origin:"))
        self.safeRouteDestinationLabel.setText(self.tr("Destination:"))
        self.fetchSafeRouteButton.setText(self.tr("Fetch Safe Route"))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    translator = QTranslator()
    lang = QLocale.system().name()
    if "fr" in lang:
        translator.load("fr.qm")
    elif "es" in lang:
        translator.load("es.qm")
    app.installTranslator(translator)
    ex = SEFCompanionApp()
    ex.show()
    sys.exit(app.exec_())
