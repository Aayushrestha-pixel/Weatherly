from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

db = SQLAlchemy()

# Nepal timezone
nepal_tz = pytz.timezone('Asia/Kathmandu')

def get_nepal_time():
    """Get current time in Nepal timezone"""
    return datetime.now(nepal_tz)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    preferred_city = db.Column(db.String(100), default='Kathmandu')
    created_at = db.Column(db.DateTime, default=get_nepal_time)
    
    # Relationship with tasks
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_name = db.Column(db.String(200), nullable=False)
    ai_suggestion = db.Column(db.Text, nullable=True)
    risk_level = db.Column(db.String(20), default='none')  # none, low, medium, high
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=get_nepal_time)

    # for smart scheduling
    suitability_score = db.Column(db.Float, default=0.0)
    best_day_suggestion = db.Column(db.String(100), nullable=True)
    urgency_level = db.Column(db.String(20), default='LOW')
    last_analysis = db.Column(db.DateTime, nullable=True)
    
    def get_formatted_time(self):
        """Get formatted time in Nepal timezone"""
        if self.created_at:
            # If datetime is naive, assume it's UTC and localize it
            if self.created_at.tzinfo is None:
                utc_time = pytz.utc.localize(self.created_at)
                nepal_time = utc_time.astimezone(nepal_tz)
            else:
                nepal_time = self.created_at.astimezone(nepal_tz)
            
            return nepal_time.strftime('%b %d, %Y at %I:%M %p')
        return "Unknown"
    
    def __repr__(self):
        return f'<Task {self.task_name}>'