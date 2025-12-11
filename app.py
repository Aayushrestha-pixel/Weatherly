from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Task, AdminLog
from config import Config
import requests
import google.generativeai as genai
from weather_analyzer import WeatherAnalyzer, NotificationManager
from datetime import datetime, timedelta
import pytz
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure Gemini
genai.configure(api_key=app.config['GEMINI_API_KEY'])
model = genai.GenerativeModel('gemini-2.5-flash')

# Nepal timezone
nepal_tz = pytz.timezone('Asia/Kathmandu')

def get_nepal_time():
    """Get current time in Nepal timezone"""
    return datetime.now(nepal_tz)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Admin decorator
def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('⛔ Please login to access this page', 'danger')
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('⛔ Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def log_admin_action(action, target_username=None, details=None):
    """Log admin actions for security audit"""
    try:
        log = AdminLog(
            admin_username=current_user.username,
            action=action,
            target_username=target_username,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log admin action: {e}")


# Helper function to get weather emoji
def get_weather_emoji(condition):
    """Return emoji based on weather condition"""
    emoji_map = {
        'clear': '☀️',
        'clouds': '☁️',
        'rain': '🌧️',
        'drizzle': '🌦️',
        'thunderstorm': '⛈️',
        'snow': '❄️',
        'mist': '🌫️',
        'fog': '🌫️',
        'haze': '🌫️',
        'dust': '🌪️',
        'sand': '🌪️',
        'smoke': '💨',
    }
    return emoji_map.get(condition.lower(), '🌤️')


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        city = request.form.get('city', 'Kathmandu')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user (regular user, not admin)
        user = User(username=username, email=email, preferred_city=city, is_admin=False)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('🎉 Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Update last login
            user.last_login = get_nepal_time()
            db.session.commit()
            
            login_user(user)
            
            if user.is_admin:
                log_admin_action('ADMIN_LOGIN', details='Admin logged in')
                flash(f'👑 Welcome back, Admin {user.username}!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash(f'👋 Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid username or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    if current_user.is_admin:
        log_admin_action('ADMIN_LOGOUT', details='Admin logged out')
    logout_user()
    flash('👋 You have been logged out.', 'info')
    return redirect(url_for('index'))


# ============================================
# ADMIN ROUTES
# ============================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard with user statistics"""
    users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    total_users = len(users)
    total_tasks = Task.query.count()
    total_completed = Task.query.filter_by(status='completed').count()
    
    # Recent admin logs
    recent_logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).limit(10).all()
    
    # User statistics
    user_stats = []
    for user in users:
        user_stats.append({
            'user': user,
            'task_count': user.get_task_count(),
            'completed_tasks': user.get_completed_task_count(),
            'pending_tasks': user.get_pending_task_count(),
            'critical_tasks': user.get_critical_task_count()
        })
    
    log_admin_action('VIEW_DASHBOARD', details='Viewed admin dashboard')
    
    return render_template('admin_dashboard.html',
                         user_stats=user_stats,
                         total_users=total_users,
                         total_tasks=total_tasks,
                         total_completed=total_completed,
                         recent_logs=recent_logs)


@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_view_user(user_id):
    """View detailed user information (password protected)"""
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('⛔ Cannot view admin user details', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.created_at.desc()).all()
    
    log_admin_action('VIEW_USER_DATA', target_username=user.username, 
                    details=f'Viewed details for user {user.username}')
    
    return render_template('admin_user_detail.html', user=user, tasks=tasks)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Delete a user and all their data"""
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('⛔ Cannot delete admin users', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    username = user.username
    task_count = user.get_task_count()
    
    # Log before deletion
    log_admin_action('DELETE_USER', target_username=username, 
                    details=f'Deleted user {username} with {task_count} tasks')
    
    # Delete user (tasks will be cascade deleted)
    db.session.delete(user)
    db.session.commit()
    
    flash(f'🗑️ User "{username}" and {task_count} tasks deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logs')
@admin_required
def admin_logs():
    """View all admin activity logs"""
    page = request.args.get('page', 1, type=int)
    logs = AdminLog.query.order_by(AdminLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    log_admin_action('VIEW_LOGS', details='Viewed admin logs')
    
    return render_template('admin_logs.html', logs=logs)


@app.route('/admin/stats')
@admin_required
def admin_stats():
    """View system-wide statistics"""
    # User statistics
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter(User.last_login.isnot(None), User.is_admin==False).count()
    
    # Task statistics
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(status='completed').count()
    pending_tasks = Task.query.filter_by(status='pending').count()
    critical_tasks = Task.query.filter_by(urgency_level='CRITICAL').count()
    
    # Risk level distribution
    high_risk = Task.query.filter_by(risk_level='high').count()
    medium_risk = Task.query.filter_by(risk_level='medium').count()
    low_risk = Task.query.filter_by(risk_level='low').count()
    no_risk = Task.query.filter_by(risk_level='none').count()
    
    log_admin_action('VIEW_STATS', details='Viewed system statistics')
    
    return render_template('admin_stats.html',
                         total_users=total_users,
                         active_users=active_users,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks,
                         pending_tasks=pending_tasks,
                         critical_tasks=critical_tasks,
                         high_risk=high_risk,
                         medium_risk=medium_risk,
                         low_risk=low_risk,
                         no_risk=no_risk)


# ============================================
# USER ROUTES (EXISTING)
# ============================================

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    city = request.args.get('city', current_user.preferred_city)
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.desc()).all()
    
    # Get current weather
    weather_data = get_weather(city)
    
    # Get 7-day forecast
    forecast_data = get_7day_forecast(city)
    
    # Initialize analyzer
    analyzer = WeatherAnalyzer()
    notification_manager = NotificationManager(analyzer)
    
    # Generate notifications
    notifications = []
    if forecast_data:
        notifications = notification_manager.generate_notifications_for_tasks(
            tasks, 
            forecast_data
        )
    
    # Get notification summary
    notification_summary = notification_manager.get_dashboard_summary(notifications)
    
    nepal_cities = [
        'Kathmandu', 'Pokhara', 'Lalitpur', 'Bhaktapur', 'Biratnagar'
    ]
    
    return render_template('dashboard.html', 
                         tasks=tasks, 
                         weather=weather_data,
                         forecast=forecast_data,
                         notifications=notifications,
                         notification_summary=notification_summary,
                         current_city=city,
                         cities=nepal_cities,
                         get_weather_emoji=get_weather_emoji)


@app.route('/change_location', methods=['POST'])
@login_required
def change_location():
    """Change the current location and update user's preferred city"""
    new_city = request.form.get('city')
    if new_city:
        current_user.preferred_city = new_city
        db.session.commit()
        flash(f'📍 Location changed to {new_city}', 'success')
    return redirect(url_for('dashboard', city=new_city))

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    task_name = request.form.get('task_name')
    city = request.form.get('city', current_user.preferred_city)
    
    if task_name:
        # Get weather and forecast
        weather_data = get_weather(city)
        forecast_data = get_7day_forecast(city)

        # Initialize analyzer
        analyzer = WeatherAnalyzer()

        # Calculate suitability score
        suitability = analyzer.calculate_suitability_score(task_name, weather_data)

        # Convert to stars
        star_rating = analyzer.score_to_stars(suitability['score'])

        # Find best days
        best_days = []
        if forecast_data:
            best_days = analyzer.find_best_weather_window(task_name, forecast_data)

        # Calculate urgency
        urgency_data = analyzer.calculate_task_urgency(task_name, forecast_data) if forecast_data else {'urgency_level': 'LOW'}

        # Get AI analysis
        ai_suggestion = analyze_task_with_ai(task_name, weather_data, city)

        enhanced_suggestion = ai_suggestion['suggestion']
        if best_days:
            enhanced_suggestion += "\n\n📅 SMART SCHEDULING:\n"
            for i, day in enumerate(best_days, 1):
                # Use the new display_text and stars_text from analyzer
                enhanced_suggestion += f"{i}. {day['display_text']}: {day['stars_text']} {day['rating_text']}\n"

        # Create task with smart data (using Nepal time)
        task = Task(
            user_id=current_user.id,
            task_name=task_name,
            ai_suggestion=enhanced_suggestion,
            suitability_score=star_rating['stars'],
            best_day_suggestion=best_days[0]['display_text'] if best_days else None,
            urgency_level=urgency_data['urgency_level'],
            risk_level=determine_risk_level(suitability['score']),
            last_analysis=get_nepal_time(),
            created_at=get_nepal_time()
        )
        db.session.add(task)
        db.session.commit()

        flash('✅ Task added with smart scheduling analysis!', 'success')
    
    return redirect(url_for('dashboard', city=city))


def determine_risk_level(score):
    """Convert suitability score to risk level"""
    if score >= 80:
        return 'none'
    elif score >= 60:
        return 'low'
    elif score >= 40:
        return 'medium'
    else:
        return 'high'


@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        flash('🗑️ Task deleted!', 'info')
    return redirect(url_for('dashboard'))


@app.route('/toggle_task/<int:task_id>')
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        task.status = 'completed' if task.status == 'pending' else 'pending'
        db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/api/weather/<city>')
@login_required
def api_weather(city):
    """API endpoint for AJAX weather updates"""
    weather_data = get_weather(city)
    if weather_data:
        return jsonify({'success': True, 'weather': weather_data})
    return jsonify({'success': False, 'error': 'Unable to fetch weather data'})


def get_weather(city):
    """Fetch comprehensive weather data from OpenWeatherMap API"""
    api_key = app.config['OPENWEATHER_API_KEY']
    
    try:
        # Current weather
        current_url = 'https://api.openweathermap.org/data/2.5/weather'
        current_params = {
            'q': f'{city},NP',
            'appid': api_key,
            'units': 'metric'
        }
        current_response = requests.get(current_url, params=current_params, timeout=5)
        current_response.raise_for_status()
        current_data = current_response.json()
        
        # Forecast for rain chances
        forecast_url = 'https://api.openweathermap.org/data/2.5/forecast'
        forecast_params = {
            'q': f'{city},NP',
            'appid': api_key,
            'units': 'metric',
            'cnt': 8
        }
        forecast_response = requests.get(forecast_url, params=forecast_params, timeout=5)
        forecast_response.raise_for_status()
        forecast_data = forecast_response.json()
        
        # Calculate rain probability
        rain_chance = 0
        if 'list' in forecast_data:
            rain_count = sum(1 for item in forecast_data['list'] if 'rain' in item)
            rain_chance = int((rain_count / len(forecast_data['list'])) * 100)
        
        # Extract comprehensive weather info
        weather = {
            'city': city,
            'temp': round(current_data['main']['temp']),
            'feels_like': round(current_data['main']['feels_like']),
            'temp_min': round(current_data['main']['temp_min']),
            'temp_max': round(current_data['main']['temp_max']),
            'description': current_data['weather'][0]['description'].title(),
            'humidity': current_data['main']['humidity'],
            'pressure': current_data['main']['pressure'],
            'wind_speed': round(current_data['wind']['speed'], 1),
            'wind_deg': current_data['wind'].get('deg', 0),
            'clouds': current_data['clouds']['all'],
            'visibility': round(current_data.get('visibility', 10000) / 1000, 1),
            'condition': current_data['weather'][0]['main'].lower(),
            'icon': current_data['weather'][0]['icon'],
            'rain_chance': rain_chance,
            'sunrise': datetime.fromtimestamp(current_data['sys']['sunrise']).strftime('%H:%M'),
            'sunset': datetime.fromtimestamp(current_data['sys']['sunset']).strftime('%H:%M'),
        }
        return weather
    except Exception as e:
        print(f"Weather API Error: {e}")
        return None


def analyze_task_with_ai(task_name, weather_data, city):
    """Use Gemini AI to analyze the task and determine risk level"""
    if not weather_data:
        return {
            'suggestion': "Unable to fetch weather data for analysis.",
            'risk_level': 'none'
        }
    
    # Check if API key exists
    if not app.config['GEMINI_API_KEY']:
        print("ERROR: GEMINI_API_KEY not found in environment!")
        return {
            'suggestion': "⚠️ AI configuration error. Please check API key.",
            'risk_level': 'none'
        }
    
    try:
        prompt = f"""You are Weatherly, an intelligent weather assistant helping users plan their daily activities.

Task: "{task_name}"
Location: {city}, Nepal

Current Weather Conditions:
- Temperature: {weather_data['temp']}°C (Feels like {weather_data['feels_like']}°C)
- Condition: {weather_data['description']}
- Humidity: {weather_data['humidity']}%
- Wind Speed: {weather_data['wind_speed']} m/s
- Rain Chance (next 24h): {weather_data['rain_chance']}%
- Cloud Coverage: {weather_data['clouds']}%
- Visibility: {weather_data['visibility']} km

Analyze this task and provide:
1. Risk Assessment: Determine if this activity is SAFE, CAUTION, or DANGEROUS given current weather
2. Brief suggestion (2-3 sentences max) with:
   - Weather suitability for the task
   - Clothing/gear recommendations if needed
   - Timing suggestions or alternatives if weather is poor
   - Use emojis naturally to make it friendly

Important: 
- If weather is dangerous (heavy rain, storm, extreme temp), start with "⚠️ WARNING:" or "🚨 ALERT:"
- For caution conditions, start with "⚡ CAUTION:"
- For good conditions, start with "✅" or "👍"
- Keep tone friendly and Gen Z-style (casual but helpful)

At the end, add on a new line: RISK_LEVEL: [none/low/medium/high]
"""
        
        print(f"Calling Gemini API for task: {task_name}")
        response = model.generate_content(prompt)
        suggestion_text = response.text
        print(f"Gemini response received: {suggestion_text[:100]}...")
        
        # Extract risk level from AI response
        risk_level = 'none'
        if 'RISK_LEVEL:' in suggestion_text:
            parts = suggestion_text.split('RISK_LEVEL:')
            suggestion_text = parts[0].strip()
            risk_level = parts[1].strip().lower()
        elif '🚨' in suggestion_text or 'DANGEROUS' in suggestion_text.upper():
            risk_level = 'high'
        elif '⚠️' in suggestion_text or 'WARNING' in suggestion_text.upper():
            risk_level = 'high'
        elif '⚡' in suggestion_text or 'CAUTION' in suggestion_text.upper():
            risk_level = 'medium'
        elif weather_data['rain_chance'] > 60 or weather_data['temp'] < 5 or weather_data['temp'] > 35:
            risk_level = 'medium'
        elif weather_data['rain_chance'] > 30:
            risk_level = 'low'
        
        return {
            'suggestion': suggestion_text,
            'risk_level': risk_level
        }
    except Exception as e:
        print(f"❌ Gemini API Error: {type(e).__name__}: {str(e)}")
        return {
            'suggestion': "✓ Task noted. Check weather conditions above for planning.",
            'risk_level': 'none'
        }

def get_7day_forecast(city):
    """Fetch 7-day forecast from OpenWeatherMap"""
    api_key = app.config['OPENWEATHER_API_KEY']
    
    try:
        url = 'https://api.openweathermap.org/data/2.5/forecast'
        params = {
            'q': f'{city},NP',
            'appid': api_key,
            'units': 'metric',
            'cnt': 56  # 7 days * 8 (3-hour intervals)
        }
        response = requests.get(url, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        # Group by day and average
        daily_forecasts = []
        current_day = None
        day_data = []
        
        for item in data['list']:
            date = datetime.fromtimestamp(item['dt'])
            day = date.date()
            
            if current_day != day:
                if day_data:
                    # Calculate daily average
                    daily_forecasts.append({
                        'date': current_day.strftime('%Y-%m-%d'),
                        'day_name': current_day.strftime('%A'),
                        'temp': round(sum(d['temp'] for d in day_data) / len(day_data)),
                        'rain_chance': int(sum(d.get('rain', 0) for d in day_data) / len(day_data) * 100),
                        'wind_speed': round(sum(d['wind'] for d in day_data) / len(day_data), 1),
                        'humidity': int(sum(d['humidity'] for d in day_data) / len(day_data)),
                        'condition': day_data[0]['condition']
                    })
                
                current_day = day
                day_data = []
            
            day_data.append({
                'temp': item['main']['temp'],
                'rain': 1 if 'rain' in item else 0,
                'wind': item['wind']['speed'],
                'humidity': item['main']['humidity'],
                'condition': item['weather'][0]['main'].lower()
            })
        
        return daily_forecasts[:7]  # Return 7 days
    
    except Exception as e:
        print(f"Forecast Error: {e}")
        return []


# Initialize database and create admin user if doesn't exist
with app.app_context():
    db.create_all()
    
    # Create default admin if doesn't exist
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@weatherly.com',
            preferred_city='Kathmandu',
            is_admin=True
        )
        admin.set_password('admin123')  # CHANGE THIS IN PRODUCTION!
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin user created: username='admin', password='admin123'")


if __name__ == '__main__':
    app.run(debug=True, port=5000)