from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Task
from config import Config
import requests
import google.generativeai as genai
from weather_analyzer import WeatherAnalyzer, NotificationManager
from datetime import datetime, timedelta
import pytz

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
        
        # Create new user
        user = User(username=username, email=email, preferred_city=city)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('🎉 Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'👋 Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('❌ Invalid username or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('👋 You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
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


# Initialize database
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True, port=5000)