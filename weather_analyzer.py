from datetime import datetime, timedelta


class WeatherAnalyzer:
    """
    Custom weather analysis engine for task optimization
    """
    
    # Scoring weights - can be tuned
    WEIGHT_TEMP = 0.35
    WEIGHT_RAIN = 0.40
    WEIGHT_WIND = 0.15
    WEIGHT_HUMIDITY = 0.10
    
    # Temperature thresholds for different comfort levels
    TEMP_IDEAL_MIN = 15
    TEMP_IDEAL_MAX = 25
    TEMP_ACCEPTABLE_MIN = 10
    TEMP_ACCEPTABLE_MAX = 30
    
    # Task category definitions
    OUTDOOR_KEYWORDS = [
    'hiking', 'jogging', 'running', 'walk', 'walking',
    'cycle', 'cycling', 'bike', 'biking', 'ride', 'riding',
    'picnic', 'park', 'outdoor', 'garden', 'yard', 'backyard',
    'sport', 'sports', 'football', 'soccer', 'cricket',
    'basketball', 'volleyball', 'badminton', 'tennis',
    'trek', 'trekking', 'camp', 'camping', 'climb', 'climbing',
    'trail', 'swim', 'swimming', 'beach', 'sunbathe', 'sunbathing',
    'skate', 'skating', 'skateboard', 'skateboarding',
    'surf', 'surfing', 'kayak', 'kayaking', 'canoe', 'canoeing',
    'fishing', 'hunt', 'hunting',
    'photography', 'nature', 'explore', 'exploring',
    'field', 'fieldwork', 'gardening',
    'dog walk', 'walk dog', 'run errands', 'errands', 'travel', 'trip'
]
    
    def __init__(self):
        self.analysis_cache = {}
    
    def calculate_suitability_score(self, task_name, weather_data):
        """
        MAIN ALGORITHM: Calculate weather suitability score for a task
        
        Args:
            task_name (str): Name of the task
            weather_data (dict): Weather information
        
        Returns:
            dict: {
                'score': float (0-100),
                'rating': str ('Excellent', 'Good', 'Fair', 'Poor'),
                'factors': dict (breakdown of score components)
            }
        """
        # Determine if task is outdoor
        is_outdoor = self._is_outdoor_task(task_name)
        
        if not is_outdoor:
            # Indoor tasks - weather has minimal impact
            return {
                'score': 95.0,
                'rating': 'Excellent',
                'factors': {
                    'message': 'Indoor activity - weather independent'
                }
            }
    
        
        # Calculate component scores
        temp_score = self._score_temperature(weather_data['temp'])
        rain_score = self._score_rain(weather_data['rain_chance'])
        wind_score = self._score_wind(weather_data['wind_speed'])
        humidity_score = self._score_humidity(weather_data['humidity'])
        
        # Weighted combination
        final_score = (
            temp_score * self.WEIGHT_TEMP +
            rain_score * self.WEIGHT_RAIN +
            wind_score * self.WEIGHT_WIND +
            humidity_score * self.WEIGHT_HUMIDITY
        )
        
        # Determine rating
        if final_score >= 80:
            rating = 'Excellent'
        elif final_score >= 60:
            rating = 'Good'
        elif final_score >= 40:
            rating = 'Fair'
        else:
            rating = 'Poor'
        
        return {
            'score': round(final_score, 2),
            'rating': rating,
            'factors': {
                'temperature': round(temp_score, 1),
                'rain': round(rain_score, 1),
                'wind': round(wind_score, 1),
                'humidity': round(humidity_score, 1)
            }
        }
    
    def _score_temperature(self, temp):
        """Score temperature comfort (0-100)"""
        if self.TEMP_IDEAL_MIN <= temp <= self.TEMP_IDEAL_MAX:
            return 100.0
        elif self.TEMP_ACCEPTABLE_MIN <= temp <= self.TEMP_ACCEPTABLE_MAX:
            # Linear decrease as you move away from ideal range
            if temp < self.TEMP_IDEAL_MIN:
                distance = self.TEMP_IDEAL_MIN - temp
                return max(60, 100 - (distance * 8))
            else:
                distance = temp - self.TEMP_IDEAL_MAX
                return max(60, 100 - (distance * 8))
        else:
            # Too hot or too cold
            if temp < self.TEMP_ACCEPTABLE_MIN:
                return max(0, 60 - (self.TEMP_ACCEPTABLE_MIN - temp) * 10)
            else:
                return max(0, 60 - (temp - self.TEMP_ACCEPTABLE_MAX) * 10)
    
    def _score_rain(self, rain_chance):
        """Score rain probability (0-100)"""
        if rain_chance < 20:
            return 100.0
        elif rain_chance < 40:
            return 80.0
        elif rain_chance < 60:
            return 50.0
        elif rain_chance < 80:
            return 25.0
        else:
            return 10.0
    
    def _score_wind(self, wind_speed):
        """Score wind conditions (0-100)"""
        if wind_speed < 5:
            return 100.0
        elif wind_speed < 10:
            return 80.0
        elif wind_speed < 15:
            return 50.0
        elif wind_speed < 20:
            return 25.0
        else:
            return 10.0
    
    def _score_humidity(self, humidity):
        """Score humidity comfort (0-100)"""
        if 40 <= humidity <= 60:
            return 100.0
        elif 30 <= humidity <= 70:
            return 80.0
        elif 20 <= humidity <= 80:
            return 60.0
        else:
            return 40.0
    
    def _is_outdoor_task(self, task_name):
        """Determine if task is outdoor-related"""
        task_lower = task_name.lower()
        return any(keyword in task_lower for keyword in self.OUTDOOR_KEYWORDS)
    
    def score_to_stars(self, score):
        """
        Convert suitability score (0-100) to star rating (1-5)
        
        Returns:
            dict: {
                'stars': int (1-5),
                'stars_html': str (HTML with stars),
                'stars_text': str (★★★★★),
                'rating_text': str (e.g., "Excellent")
            }
        """
        # Convert 0-100 score to 1-5 stars
        if score >= 90:
            stars = 5
            rating_text = "Excellent"
        elif score >= 75:
            stars = 4
            rating_text = "Very Good"
        elif score >= 60:
            stars = 3
            rating_text = "Good"
        elif score >= 40:
            stars = 2
            rating_text = "Fair"
        else:
            stars = 1
            rating_text = "Poor"
        
        # Generate star text (★★★★★ or ☆☆☆☆☆)
        filled_stars = '★' * stars
        empty_stars = '☆' * (5 - stars)
        stars_text = filled_stars + empty_stars
        
        # Generate HTML for stars (for display)
        stars_html = ''
        for i in range(1, 6):
            if i <= stars:
                stars_html += '<i class="fas fa-star star-filled"></i>'
            else:
                stars_html += '<i class="far fa-star star-empty"></i>'
        
        return {
            'stars': stars,
            'stars_html': stars_html,
            'stars_text': stars_text,
            'rating_text': rating_text,
            'score': score  # Keep original score for reference
        }

    def get_star_breakdown(self, score):
        """
        Get detailed star breakdown (like Amazon reviews)
        
        Returns:
            dict: Percentage breakdown of each factor
        """
        stars = self.score_to_stars(score)['stars']
        
        # Calculate percentage
        percentage = (stars / 5.0) * 100
        
        return {
            'stars': stars,
            'percentage': round(percentage, 1),
            'bar_width': percentage
        }
    
    def find_best_weather_window(self, task_name, forecast_list):
        """
        ALGORITHM: Find optimal days in forecast period
        
        Args:
            task_name (str): Task description
            forecast_list (list): List of weather forecasts (7 days)
        
        Returns:
            list: Top 3 optimal days with scores, stars, dates and recommendations
        """
        results = []
        
        for forecast in forecast_list:
            score_data = self.calculate_suitability_score(task_name, forecast)
            star_data = self.score_to_stars(score_data['score'])
            
            # Parse date and format it
            date_str = forecast.get('date', '')
            day_name = forecast.get('day_name', '')
            
            # Create formatted date string
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                formatted_date = date_obj.strftime('%b %d')  # e.g., "Dec 12"
                display_text = f"{day_name} ({formatted_date})"
            except:
                display_text = day_name
            
            results.append({
                'date': date_str,
                'day_name': day_name,
                'formatted_date': formatted_date if 'date_obj' in locals() else '',
                'display_text': display_text,
                'score': score_data['score'],
                'rating': score_data['rating'],
                'stars': star_data['stars'],
                'stars_text': star_data['stars_text'],
                'stars_html': star_data['stars_html'],
                'rating_text': star_data['rating_text'],
                'weather': {
                    'temp': forecast['temp'],
                    'condition': forecast.get('condition', 'Unknown'),
                    'rain_chance': forecast['rain_chance']
                },
                'recommendation': self._generate_recommendation(score_data)
            })
        
        # Sort by score descending
        results.sort(key=lambda x: x['score'], reverse=True)
        
        return results[:3]  # Return top 3 days
    
    def _generate_recommendation(self, score_data):
        """Generate human-readable recommendation"""
        score = score_data['score']
        
        if score >= 80:
            return "Perfect conditions! Highly recommended."
        elif score >= 60:
            return "Good conditions. Should be comfortable."
        elif score >= 40:
            return "Acceptable. Consider weather precautions."
        else:
            return "Not recommended. Consider rescheduling."
    
    def calculate_task_urgency(self, task_name, forecast_list):
        """
        ALGORITHM: Calculate urgency based on weather window availability
        
        Returns:
            dict: {
                'urgency_level': str ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'),
                'urgency_score': int (0-100),
                'reason': str,
                'suitable_days_count': int
            }
        """
        # Find suitable days (score >= 60)
        suitable_days = []
        for forecast in forecast_list:
            score_data = self.calculate_suitability_score(task_name, forecast)
            if score_data['score'] >= 60:
                # Format the date nicely
                day_name = forecast.get('day_name', '')
                date_str = forecast.get('date', '')
                try:
                    date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                    formatted_date = date_obj.strftime('%b %d')
                    display = f"{day_name} ({formatted_date})"
                except:
                    display = day_name
                
                suitable_days.append(display)
        
        suitable_count = len(suitable_days)
        
        # Determine urgency
        if suitable_count == 0:
            urgency_level = 'CRITICAL'
            urgency_score = 100
            reason = "No suitable weather windows in the forecast!"
        elif suitable_count == 1:
            urgency_level = 'HIGH'
            urgency_score = 80
            reason = f"Only 1 good day available: {suitable_days[0]}"
        elif suitable_count <= 2:
            urgency_level = 'MEDIUM'
            urgency_score = 50
            reason = f"Limited weather windows: {', '.join(suitable_days)}"
        else:
            urgency_level = 'LOW'
            urgency_score = 20
            reason = f"Multiple good days available: {suitable_count} days"
        
        return {
            'urgency_level': urgency_level,
            'urgency_score': urgency_score,
            'reason': reason,
            'suitable_days_count': suitable_count,
            'suitable_days': suitable_days
        }


class NotificationManager:
    """
    Manages weather-based notifications and alerts
    """
    
    def __init__(self, weather_analyzer):
        self.analyzer = weather_analyzer
        self.notifications = []
    
    def generate_notifications_for_tasks(self, tasks, forecast_list):
        """
        Generate notifications for all user tasks
        
        Returns:
            list: Notification objects with urgency and messages
        """
        notifications = []
        
        for task in tasks:
            # Skip completed tasks
            if task.status == 'completed':
                continue
            
            # Calculate urgency
            urgency_data = self.analyzer.calculate_task_urgency(
                task.task_name, 
                forecast_list
            )
            
            # Only notify for HIGH and CRITICAL urgency
            if urgency_data['urgency_level'] in ['HIGH', 'CRITICAL']:
                
                # Find best day
                best_days = self.analyzer.find_best_weather_window(
                    task.task_name, 
                    forecast_list
                )
                
                notification = {
                    'task_id': task.id,
                    'task_name': task.task_name,
                    'urgency': urgency_data['urgency_level'],
                    'message': self._create_notification_message(
                        task.task_name,
                        urgency_data,
                        best_days[0] if best_days else None
                    ),
                    'icon': '🚨' if urgency_data['urgency_level'] == 'CRITICAL' else '⚠️',
                    'action_required': True,
                    'best_day': best_days[0] if best_days else None
                }
                
                notifications.append(notification)
        
        return notifications
    
    def _create_notification_message(self, task_name, urgency_data, best_day):
        """Create user-friendly notification message"""
        if urgency_data['urgency_level'] == 'CRITICAL':
            return f"🚨 CRITICAL: No suitable weather for '{task_name}' in the next 7 days! Consider indoor alternative or wait for better forecast."
        
        elif urgency_data['urgency_level'] == 'HIGH':
            if best_day:
                return f"⚠️ LIMITED TIME: Only 1 good day for '{task_name}' - {best_day['display_text']} ({best_day['rating_text']} conditions). Schedule soon!"
            else:
                return f"⚠️ Act soon: Limited weather windows for '{task_name}'"
        
        return urgency_data['reason']
    
    def get_dashboard_summary(self, notifications):
        """
        Generate summary for dashboard display
        """
        critical = len([n for n in notifications if n['urgency'] == 'CRITICAL'])
        high = len([n for n in notifications if n['urgency'] == 'HIGH'])
        
        if critical > 0:
            return {
                'level': 'danger',
                'message': f"🚨 {critical} critical weather alerts!",
                'count': critical + high
            }
        elif high > 0:
            return {
                'level': 'warning',
                'message': f"⚠️ {high} time-sensitive weather windows",
                'count': high
            }
        else:
            return {
                'level': 'success',
                'message': "✅ All tasks have good weather windows",
                'count': 0
            }