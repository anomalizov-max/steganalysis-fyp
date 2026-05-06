from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    """User model for authentication and authorization"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    analyses = db.relationship('Analysis', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Analysis(db.Model):
    """Analysis model to store file analysis results"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(10))
    
    # Analysis results
    analyzed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    has_hidden_data = db.Column(db.Boolean, default=False)
    confidence_score = db.Column(db.Float)
    
    # Detection method results
    lsb_detection_score = db.Column(db.Float)
    statistical_score = db.Column(db.Float)
    ml_detection_score = db.Column(db.Float)
    
    # Extracted data info
    extracted_data_available = db.Column(db.Boolean, default=False)
    extracted_data_path = db.Column(db.String(512))
    extracted_data_preview = db.Column(db.Text)  # Preview of extracted content
    extracted_data_type = db.Column(db.String(50))  # Type: text, binary, ZIP, etc.
    extracted_data_size = db.Column(db.Integer)  # Size in bytes
    extraction_method = db.Column(db.String(50))
    hidden_filename = db.Column(db.String(255))  # Name of the file hidden inside the image
    
    # Additional metadata
    image_width = db.Column(db.Integer)
    image_height = db.Column(db.Integer)
    image_mode = db.Column(db.String(20))
    analysis_notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Analysis {self.id} - {self.original_filename}>'

class AnalysisLog(db.Model):
    """Detailed logs for each analysis operation"""
    id = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analysis.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_level = db.Column(db.String(20))  # INFO, WARNING, ERROR
    message = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON formatted additional details
    
    analysis = db.relationship('Analysis', backref=db.backref('logs', lazy='dynamic', cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<AnalysisLog {self.id} - {self.log_level}>'
