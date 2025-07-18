
Lines 1 to 931 of fixed code on 7-18-2025- Got stopped by “message too long” when Claud was rewriting the code below:

import os
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import json
import numpy as np
from scipy.stats import norm
import yfinance as yf

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///shadowstrike.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_key_here')
app.config['STRIPE_PUBLIC_KEY'] = os.environ.get('STRIPE_PUBLIC_KEY', 'pk_test_your_key_here')

# Email configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'your-email@gmail.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', 'your-app-password')

# Initialize database
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    subscription_status = db.Column(db.String(20), default='trial')
    trial_end_date = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    subscription_start_date = db.Column(db.DateTime)
    subscription_end_date = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    theme_color = db.Column(db.String(10), default='#10b981')
    email_alerts_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def days_left_in_trial(self):
        if self.subscription_status == 'trial':
            return max(0, (self.trial_end_date - datetime.utcnow()).days)
        return 0

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    symbol = db.Column(db.String(10), nullable=False)
    option_type = db.Column(db.String(10), nullable=False)  # 'call' or 'put'
    strike_price = db.Column(db.Float, nullable=False)
    entry_price = db.Column(db.Float, nullable=False)
    current_price = db.Column(db.Float, default=0.0)
    quantity = db.Column(db.Integer, nullable=False)
    broker_fee = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(10), default='open')  # 'open', 'closed'
    pnl = db.Column(db.Float, default=0.0)
    stop_loss = db.Column(db.Float)
    target_price = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at = db.Column(db.DateTime)

# Utility Functions
def send_email_async(to_email, subject, html_content):
    """Send email asynchronously"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SMTP_USERNAME
        msg['To'] = to_email
        
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email to {to_email}: {str(e)}")

def get_stock_price(symbol):
    """Get stock price using Yahoo Finance"""
    try:
        ticker = yf.Ticker(symbol)
        data = ticker.history(period="1d")
        if not data.empty:
            return {
                'price': float(data['Close'].iloc[-1]),
                'change': float(data['Close'].iloc[-1] - data['Open'].iloc[-1]),
                'change_percent': float(((data['Close'].iloc[-1] - data['Open'].iloc[-1]) / data['Open'].iloc[-1]) * 100)
            }
    except Exception as e:
        print(f"Error getting stock price for {symbol}: {str(e)}")
    
    # Fallback mock data
    return {
        'price': 100.0,
        'change': 1.5,
        'change_percent': 1.5
    }

def get_market_status():
    """Get market status"""
    now = datetime.now()
    if now.weekday() < 5 and 9 <= now.hour < 16:  # Monday-Friday 9AM-4PM
        return {
            'status': 'Open',
            'next_open': 'Currently Open'
        }
    else:
        return {
            'status': 'Closed',
            'next_open': 'Next Monday 9:30 AM ET'
        }

def get_top_movers():
    """Get top market movers"""
    symbols = ['SPY', 'QQQ', 'IWM', 'GLD', 'SLV', 'TSLA', 'AAPL', 'NVDA', 'MSFT', 'GOOGL']
    movers = []
    
    for symbol in symbols:
        try:
            stock_data = get_stock_price(symbol)
            movers.append({
                'symbol': symbol,
                'price': stock_data['price'],
                'change': stock_data['change'],
                'change_percent': stock_data['change_percent']
            })
        except Exception as e:
            print(f"Error getting data for {symbol}: {str(e)}")
    
    return sorted(movers, key=lambda x: abs(x['change_percent']), reverse=True)[:10]

def fetch_options_data(symbol):
    """Fetch options data (mock implementation)"""
    # This would normally connect to an options data provider
    # For demo purposes, returning mock data
    mock_options = []
    base_price = get_stock_price(symbol)['price']
    
    for i in range(10):
        strike = base_price + (i - 5) * 5
        mock_options.append({
            'symbol': symbol,
            'type': 'call' if i % 2 == 0 else 'put',
            'strike': strike,
            'expiration': (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
            'price': max(0.5, abs(base_price - strike) * 0.1 + 2.0),
            'impliedVolatility': 25.0 + (i * 2),
            'daysToExpiry': 30 - i
        })
    
    return mock_options

def black_scholes(S, K, T, r, sigma, option_type):
    """Calculate Black-Scholes probability"""
    try:
        d1 = (np.log(S/K) + (r + 0.5*sigma**2)*T) / (sigma*np.sqrt(T))
        d2 = d1 - sigma*np.sqrt(T)
        
        if option_type.lower() == 'call':
            prob_itm = norm.cdf(d2)
            prob_otm = 1 - prob_itm
        else:
            prob_itm = norm.cdf(-d2)
            prob_otm = 1 - prob_itm
        
        return round(prob_itm * 100, 2), round(prob_otm * 100, 2)
    except Exception as e:
        print(f"Error in black_scholes calculation: {str(e)}")
        return 50.0, 50.0

def analyze_stock(symbol):
    """Analyze stock for trading signals"""
    try:
        ticker = yf.Ticker(symbol)
        data = ticker.history(period="30d")
        
        if not data.empty:
            current_price = float(data['Close'].iloc[-1])
            sma_20 = data['Close'].rolling(window=20).mean().iloc[-1]
            
            signals = current_price > sma_20  # Simple signal: price above 20-day SMA
            
            return {
                'signals': signals,
                'recommendation': 'BUY' if signals else 'HOLD',
                'details': {
                    'Price': current_price,
                    'SMA20': float(sma_20),
                    'Signal': 'Bullish' if signals else 'Neutral'
                }
            }
    except Exception as e:
        print(f"Error analyzing {symbol}: {str(e)}")
    
    return {
        'signals': False,
        'recommendation': 'HOLD',
        'details': {'Price': 100.0, 'SMA20': 98.0, 'Signal': 'Neutral'}
    }

def calculate_vertical_spread(symbol, options):
    """Calculate vertical spread opportunities"""
    try:
        calls = [opt for opt in options if opt['type'] == 'call']
        if len(calls) >= 2:
            buy_option = calls[0]
            sell_option = calls[1]
            
            max_profit = abs(sell_option['strike'] - buy_option['strike']) - abs(sell_option['price'] - buy_option['price'])
            max_loss = abs(sell_option['price'] - buy_option['price'])
            
            return {
                'type': 'call_spread',
                'buy_strike': buy_option['strike'],
                'sell_strike': sell_option['strike'],
                'max_profit': max_profit,
                'max_loss': max_loss,
                'breakeven': buy_option['strike'] + max_loss,
                'probability': 65.0  # Mock probability
            }
    except Exception as e:
        print(f"Error calculating spread for {symbol}: {str(e)}")
    
    return None

# Routes
@app.route('/')
def index():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        color = request.form.get('color', '#10b981')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            theme_color=color
        )
        
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        flash('Registration successful! Your 30-day trial has started.', 'success')
        
        # Send welcome email
        welcome_content = f"""
        <html>
        <body style="font-family: Arial; background: #1f2937; color: white; padding: 40px;">
            <div style="max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #065f46, #10b981); padding: 30px; border-radius: 15px;">
                <h1 style="color: #ffffff; text-align: center;">Welcome to ShadowStrike Options!</h1>
                <p>Hi {username},</p>
                <p>Your 30-day trial has started. You now have access to:</p>
                <ul>
                    <li>Real-time options analysis</li>
                    <li>Advanced options scanner</li>
                    <li>Portfolio tracking</li>
                    <li>Daily trading alerts</li>
                </ul>
                <p>Start trading: <a href="https://shadowstrike-options-2025.onrender.com/dashboard" style="color: #ffffff;">Go to Dashboard</a></p>
            </div>
        </body>
        </html>
        """
        threading.Thread(target=send_email_async, args=(email, "Welcome to ShadowStrike Options!", welcome_content)).start()
        
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # In a real app, you'd generate a secure token and send reset link
            flash('Password reset instructions sent to your email', 'info')
        else:
            flash('Email not found', 'error')
    
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access dashboard', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user or (user.subscription_status == 'trial' and datetime.utcnow() > user.trial_end_date):
        flash('Your trial has expired. Please subscribe.', 'error')
        return redirect(url_for('subscribe'))
    
    market_status = get_market_status()
    top_movers = get_top_movers()
    trades = Trade.query.filter_by(user_id=session['user_id']).all()
    
    total_pnl = 0
    open_trades = 0
    enhanced_trades = []
    
    for trade in trades:
        if trade.status == 'open':
            open_trades += 1
            stock_data = get_stock_price(trade.symbol)
            current_stock_price = stock_data['price']
            
            options = fetch_options_data(trade.symbol)
            current_option = next((opt for opt in options if opt['type'] == trade.option_type and opt['strike'] == trade.strike_price), None)
            current_price = current_option['price'] if current_option else trade.entry_price
            
            pnl = (current_price - trade.entry_price) * trade.quantity * 100 - trade.broker_fee * trade.quantity
            trade.pnl = round(pnl, 2)
            total_pnl += pnl
            
            enhanced_trades.append({
                'trade': trade,
                'current_stock_price': current_stock_price,
                'current_option_price': round(current_price, 2),
                'pnl': trade.pnl
            })
    
    return render_template('dashboard.html', 
                         user=user, 
                         trades=enhanced_trades, 
                         total_pnl=round(total_pnl, 2),
                         open_trades=open_trades,
                         market_status=market_status,
                         top_movers=top_movers)

@app.route('/subscribe')
def subscribe():
    if 'user_id' not in session:
        flash('Please login to subscribe', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user.subscription_status == 'active':
        flash('You already have an active subscription!', 'info')
        return redirect(url_for('dashboard'))
    
    return render_template('subscribe.html', 
                         stripe_public_key=app.config['STRIPE_PUBLIC_KEY'],
                         user=user)

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': 'ShadowStrike Subscription'},
                    'unit_amount': 4900,
                    'recurring': {'interval': 'month'}
                },
                'quantity': 1
            }],
            mode='subscription',
            success_url='https://shadowstrike-options-2025.onrender.com/dashboard',
            cancel_url='https://shadowstrike-options-2025.onrender.com/subscribe'
        )
        
        # Update user subscription info
        user = User.query.get(session['user_id'])
        user.stripe_customer_id = checkout_session.customer
        user.stripe_subscription_id = checkout_session.subscription
        user.subscription_status = 'active'
        user.subscription_start_date = datetime.utcnow()
        user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
        db.session.commit()
        
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/market-data')
def market_data():
    market_status = get_market_status()
    top_movers = get_top_movers()
    return render_template('market_data.html', 
                         market_status=market_status, 
                         top_movers=top_movers)

@app.route('/api/top10', methods=['GET'])
def get_top10():
    symbols = ['SPY', 'QQQ', 'GLD', 'SLV']
    results = []
    
    for symbol in symbols:
        analysis = analyze_stock(symbol)
        options = fetch_options_data(symbol)
        
        for opt in options[:2]:
            S = analysis['details'].get('Price', 100)
            prob_itm, prob_otm = black_scholes(S, opt['strike'], opt['daysToExpiry']/365, 0.05, opt['impliedVolatility']/100, opt['type'])
            
            results.append({
                'symbol': symbol,
                'type': opt['type'],
                'strike': opt['strike'],
                'expiration': opt['expiration'],
                'price': opt['price'],
                'probabilityITM': prob_itm,
                'probabilityOTM': prob_otm,
                'signals': analysis['signals'],
                'score': prob_itm + (10 if analysis['signals'] else 0)
            })
        
        spread = calculate_vertical_spread(symbol, options)
        if spread:
            results.append({
                'symbol': symbol,
                'type': spread['type'],
                'buy_strike': spread['buy_strike'],
                'sell_strike': spread['sell_strike'],
                'max_profit': spread['max_profit'],
                'max_loss': spread['max_loss'],
                'breakeven': spread['breakeven'],
                'probabilityITM': spread['probability']
            })
    
    results.sort(key=lambda x: x['score'] if 'score' in x else x['probabilityITM'], reverse=True)
    
    # Send daily picks email (8-9 AM)
    now = datetime.now()
    if now.weekday() < 5 and 8 <= now.hour < 9:
        for user in User.query.filter_by(email_alerts_enabled=True).all():
            content = f"""
            <html>
            <body style="font-family: Arial; background: #1f2937; color: white; padding: 40px;">
                <div style="max-width: 600px; margin: 0 auto; background: linear-gradient(135deg, #065f46, #10b981); padding: 30px; border-radius: 15px;">
                    <h1 style="color: #ffffff; text-align: center;">🎯 Daily Top 10 Picks</h1>
                    <ul>{''.join([f"<li>{item['symbol']} {item['type']} ${item['strike'] or item['buy_strike']}: {item['probabilityITM']}% ITM</li>" for item in results[:10]])}</ul>
                </div>
            </body>
            </html>
            """
            threading.Thread(target=send_email_async, args=(user.email, "ShadowStrike Daily Picks", content)).start()
    
    return jsonify(results[:10])

@app.route('/api/portfolio', methods=['GET', 'POST'])
def portfolio():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if request.method == 'POST':
        data = request.get_json()
        trade = Trade(
            user_id=session['user_id'],
            symbol=data['symbol'],
            option_type=data['type'],
            strike_price=data['strike'] or data['buy_strike'],
            entry_price=data['price'],
            quantity=data['contracts'],
            broker_fee=0.65 * data['contracts'],
            stop_loss=data.get('stop_loss'),
            target_price=data.get('target_price')
        )
        db.session.add(trade)
        db.session.commit()
        return jsonify({'message': 'Trade added'})
    
    trades = Trade.query.filter_by(user_id=session['user_id']).all()
    for trade in trades:
        if trade.status == 'open':
            options = fetch_options_data(trade.symbol)
            current = next((opt for opt in options if opt['type'] == trade.option_type and opt['strike'] == trade.strike_price), None)
            trade.current_price = current['price'] if current else trade.entry_price
            trade.pnl = (trade.current_price - trade.entry_price) * trade.quantity * 100 - trade.broker_fee
    
    return jsonify([{
        'symbol': t.symbol,
        'type': t.option_type,
        'strike': t.strike_price,
        'entry_price': t.entry_price,
        'current_price': t.current_price,
        'pnl': t.pnl,
        'contracts': t.quantity,
        'stop_loss': t.stop_loss,
        'target_price': t.target_price
    } for t in trades])

@app.route('/api/scanner', methods=['GET'])
def scanner():
    symbols = ['SPY', 'QQQ', 'GLD', 'SLV']
    results = []
    
    for symbol in symbols:
        analysis = analyze_stock(symbol)
        options = fetch_options_data(symbol)
        
        for opt in options[:2]:
            S = analysis['details'].get('Price', 100)
            prob_itm, prob_otm = black_scholes(S, opt['strike'], opt['daysToExpiry']/365, 0.05, opt['impliedVolatility']/100, opt['type'])
            
            results.append({
                'symbol': symbol,
                'type': opt['type'],
                'strike': opt['strike'],
                'expiration': opt['expiration'],
                'price': opt['price'],
                'probabilityITM': prob_itm,
                'probabilityOTM': prob_otm,
                'recommendation': analysis['recommendation']
            })
        
        spread = calculate_vertical_spread(symbol, options)
        if spread:
            results.append({
                'symbol': symbol,
                'type': spread['type'],
                'buy_strike': spread['buy_strike'],
                'sell_strike': spread['sell_strike'],
                'max_profit': spread['max_profit'],
                'max_loss': spread['max_loss'],
                'breakeven': spread['breakeven'],
                'probabilityITM': spread['probability']
            })
    
    results.sort(key=lambda x: x['probabilityITM'], reverse=True)
    return jsonify(results[:10])

@app.route('/api/trade-scenario', methods=['POST'])
def trade_scenario():
    data = request.get_json()
    symbol = data.get('symbol')
    target_price = data.get('target_price')
    
    options = fetch_options_data(symbol)
    results = []
    
    for opt in options[:5]:
        S = target_price
        prob_itm, prob_otm = black_scholes(S, opt['strike'], opt['daysToExpiry']/365, 0.05, opt['impliedVolatility']/100, opt['type'])
        
        results.append({
            'symbol': symbol,
            'type': opt['type'],
            'strike': opt['strike'],
            'expiration': opt['expiration'],
            'price': opt['price'],
            'probabilityITM': prob_itm,
            'probabilityOTM': prob_otm
        })
    
    return jsonify(results)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/mobile-demo')
def mobile_demo():
    return render_template('mobile_demo.html')

# Create HTML Templates
welcome_html = """
<!DOCTYPE html>
<html><head><title>ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-2xl mx-auto bg-gray-800/50 p-10 rounded-2xl shadow-2xl text-center">
        <h1 class="text-4xl font-bold text-emerald-400 mb-6">🎯 ShadowStrike Options</h1>
        <p class="text-lg text-emerald-100 mb-8">Elite Trading Platform for Options Traders</p>
        <div class="space-y-4">
            <a href="/login" class="block bg-emerald-500 text-white py-3 px-6 rounded-lg font-bold hover:bg-emerald-600 transition">Login</a>
            <a href="/register" class="block bg-emerald-500 text-white py-3 px-6 rounded-lg font-bold hover:bg-emerald-600 transition">Start 30-Day Trial</a>
            <a href="/mobile-demo" class="block bg-emerald-500 text-white py-3 px-6 rounded-lg font-bold hover:bg-emerald-600 transition">Mobile Demo</a>
        </div>
    </div>
</body></html>
"""

login_html = """
<!DOCTYPE html>
<html><head><title>Login - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-md mx-auto bg-gray-800/50 p-8 rounded-2xl shadow-2xl">
        <h1 class="text-3xl font-bold text-emerald-400 text-center mb-6">🎯 ShadowStrike Options</h1>
        <h2 class="text-xl text-center mb-6">Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="mb-4 p-4 rounded-lg {% if category == 'error' %}bg-red-500/20 text-red-300{% else %}bg-green-500/20 text-green-300{% endif %}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endwith %}
        <form method="POST" class="space-y-4">
            <div>
                <label class="block text-emerald-300">Email</label>
                <input name="email" type="email" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <div>
                <label class="block text-emerald-300">Password</label>
                <input name="password" type="password" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <button type="submit" class="w-full bg-emerald-500 text-white py-3 rounded-lg font-bold hover:bg-emerald-600">Login</button>
        </form>
<p class="text-center mt-4">
            <a href="/reset-password" class="text-emerald-300 hover:underline">Forgot Password?</a> | 
            <a href="/register" class="text-emerald-300 hover:underline">Register</a>
        </p>
    </div>
</body></html>
"""

register_html = """
<!DOCTYPE html>
<html><head><title>Register - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-md mx-auto bg-gray-800/50 p-8 rounded-2xl shadow-2xl">
        <h1 class="text-3xl font-bold text-emerald-400 text-center mb-6">🎯 ShadowStrike Options</h1>
        <h2 class="text-xl text-center mb-6">Register</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="mb-4 p-4 rounded-lg {% if category == 'error' %}bg-red-500/20 text-red-300{% else %}bg-green-500/20 text-green-300{% endif %}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endwith %}
        <form method="POST" class="space-y-4">
            <div>
                <label class="block text-emerald-300">Username</label>
                <input name="username" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <div>
                <label class="block text-emerald-300">Email</label>
                <input name="email" type="email" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <div>
                <label class="block text-emerald-300">Password</label>
                <input name="password" type="password" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <div>
                <label class="block text-emerald-300">Theme Color (e.g., #10b981)</label>
                <input name="color" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" value="#10b981">
            </div>
            <button type="submit" class="w-full bg-emerald-500 text-white py-3 rounded-lg font-bold hover:bg-emerald-600">Start 30-Day Trial</button>
        </form>
        <p class="text-center mt-4">
            <a href="/login" class="text-emerald-300 hover:underline">Already have an account?</a>
        </p>
    </div>
</body></html>
"""

reset_password_html = """
<!DOCTYPE html>
<html><head><title>Reset Password - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-md mx-auto bg-gray-800/50 p-8 rounded-2xl shadow-2xl">
        <h1 class="text-3xl font-bold text-emerald-400 text-center mb-6">🔐 Reset Password</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <div class="mb-4 p-4 rounded-lg {% if category == 'error' %}bg-red-500/20 text-red-300{% else %}bg-green-500/20 text-green-300{% endif %}">
                    {{ message }}
                </div>
            {% endfor %}
        {% endwith %}
        <form method="POST" class="space-y-4">
            <div>
                <label class="block text-emerald-300">Email</label>
                <input name="email" type="email" class="w-full p-3 rounded-lg bg-gray-700 border border-emerald-500 text-white" required>
            </div>
            <button type="submit" class="w-full bg-emerald-500 text-white py-3 rounded-lg font-bold hover:bg-emerald-600">Send Reset Email</button>
        </form>
        <p class="text-center mt-4">
            <a href="/login" class="text-emerald-300 hover:underline">Back to Login</a>
        </p>
    </div>
</body></html>
"""

dashboard_html = """
<!DOCTYPE html>
<html><head><title>Dashboard - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans">
    <div class="max-w-5xl mx-auto p-6">
        <h1 class="text-3xl font-bold text-emerald-400 mb-6">🎯 ShadowStrike Options - Dashboard</h1>
        <p class="text-emerald-100">Welcome {{ user.username }}! ({{ user.subscription_status }} - {% if user.subscription_status == 'trial' %}{{ user.days_left_in_trial() }} days left{% else %}Active{% endif %})</p>
        {% if user.subscription_status == 'trial' and user.days_left_in_trial() <= 7 %}
        <div class="bg-red-500/20 p-4 rounded-lg mb-6">
            <p class="text-red-300">⚠️ Trial expires in {{ user.days_left_in_trial() }} days! <a href="/subscribe" class="text-emerald-300 hover:underline">Subscribe now</a></p>
        </div>
        {% endif %}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-gray-800/50 p-6 rounded-lg">
                <h2 class="text-xl font-semibold text-emerald-300 mb-4">📊 Market Status</h2>
                <p>Status: <strong>{{ market_status.status }}</strong></p>
                <p>Next Open: {{ market_status.next_open }}</p>
            </div>
            <div class="bg-gray-800/50 p-6 rounded-lg">
                <h2 class="text-xl font-semibold text-emerald-300 mb-4">💰 Portfolio Summary</h2>
                <p>Total P&L: ${{ "%.2f"|format(total_pnl) }}</p>
                <p>Open Trades: {{ open_trades }}</p>
            </div>
        </div>
        <h2 class="text-xl font-semibold text-emerald-300 mt-6 mb-4">🚀 Top Market Movers</h2>
        <div class="overflow-x-auto">
            <table class="w-full border-collapse">
                <thead>
                    <tr class="bg-emerald-500/30">
                        <th class="p-3 text-left">Symbol</th>
                        <th class="p-3 text-left">Price</th>
                        <th class="p-3 text-left">Change</th>
                        <th class="p-3 text-left">% Change</th>
                    </tr>
                </thead>
                <tbody>
                    {% for mover in top_movers %}
                    <tr class="bg-gray-800/30">
                        <td class="p-3">{{ mover.symbol }}</td>
                        <td class="p-3">${{ "%.2f"|format(mover.price) }}</td>
                        <td class="p-3 {{ 'text-emerald-400' if mover.change >= 0 else 'text-red-400' }}">{{ "%.2f"|format(mover.change) }}</td>
                        <td class="p-3 {{ 'text-emerald-400' if mover.change_percent >= 0 else 'text-red-400' }}">{{ "%.2f"|format(mover.change_percent) }}%</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <h2 class="text-xl font-semibold text-emerald-300 mt-6 mb-4">📈 Your Trades</h2>
        <div class="overflow-x-auto">
            <table class="w-full border-collapse">
                <thead>
                    <tr class="bg-emerald-500/30">
                        <th class="p-3 text-left">Symbol</th>
                        <th class="p-3 text-left">Type</th>
                        <th class="p-3 text-left">Strike</th>
                        <th class="p-3 text-left">Entry Price</th>
                        <th class="p-3 text-left">Current Price</th>
                        <th class="p-3 text-left">P&L</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in trades %}
                    <tr class="bg-gray-800/30">
                        <td class="p-3">{{ item.trade.symbol }}</td>
                        <td class="p-3">{{ item.trade.option_type }}</td>
                        <td class="p-3">${{ "%.2f"|format(item.trade.strike_price) }}</td>
                        <td class="p-3">${{ "%.2f"|format(item.trade.entry_price) }}</td>
                        <td class="p-3">${{ "%.2f"|format(item.current_option_price) }}</td>
                        <td class="p-3 {{ 'text-emerald-400' if item.pnl >= 0 else 'text-red-400' }}">{{ "%.2f"|format(item.pnl) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <div class="mt-6 space-x-4">
            <a href="/logout" class="text-red-400 hover:underline">Logout</a>
            <a href="/subscribe" class="text-emerald-300 hover:underline">Subscribe</a>
            <a href="/mobile-demo" class="text-emerald-300 hover:underline">Mobile App</a>
        </div>
    </div>
</body></html>
"""

subscribe_html = """
<!DOCTYPE html>
<html><head><title>Subscribe - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://js.stripe.com/v3/"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-2xl mx-auto bg-gray-800/50 p-10 rounded-2xl shadow-2xl text-center">
        <h1 class="text-3xl font-bold text-emerald-400 mb-6">🚀 Continue Your Trading Success</h1>
        <p class="text-lg text-emerald-100 mb-8">Don't lose access to profitable trading opportunities!</p>
        <div class="bg-red-500/20 p-6 rounded-lg mb-8">
            <h2 class="text-xl text-red-300">⏰ {{ user.days_left_in_trial() }} Days Left in Trial</h2>
        </div>
        <div class="text-4xl font-bold text-emerald-400 mb-8">$49/month</div>
        <p class="text-emerald-100 mb-8">Cancel anytime • No long-term contracts</p>
        <div class="bg-emerald-500/10 p-6 rounded-lg mb-8">
            <h3 class="text-xl text-emerald-300 mb-4">What You Keep:</h3>
            <ul class="text-emerald-100 space-y-2">
                <li>📊 Real-time options analysis with live market data</li>
                <li>🔍 Advanced options scanner for high-probability trades</li>
                <li>📈 Portfolio tracking with live P&L calculations</li>
                <li>🚨 Daily trading alerts and opportunities</li>
                <li>📱 Mobile app access for trading on-the-go</li>
            </ul>
        </div>
        <div>
            <h3 class="text-xl text-emerald-300 mb-4">Choose Payment Method:</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <button onclick="checkout('stripe')" class="bg-blue-600 text-white py-4 px-6 rounded-lg font-bold hover:bg-blue-700">💳 Pay with Card</button>
                <button onclick="alert('PayPal payment demo')" class="bg-blue-800 text-white py-4 px-6 rounded-lg font-bold hover:bg-blue-900">🟦 PayPal</button>
            </div>
            <p class="text-emerald-100 mt-4 text-sm">🔒 Secure payment processing</p>
        </div>
        <p class="mt-6"><a href="/dashboard" class="text-emerald-300 hover:underline">⏭️ Continue Trial ({{ user.days_left_in_trial() }} days left)</a></p>
        <script>
            const stripe = Stripe('{{ stripe_public_key }}');
            function checkout(method) {
                if (method === 'stripe') {
                    fetch('/create-checkout-session', { method: 'POST' })
                        .then(response => response.json())
                        .then(session => {
                            if (session.error) {
                                alert('Error: ' + session.error);
                            } else {
                                return stripe.redirectToCheckout({ sessionId: session.id });
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            alert('Error: ' + error.message);
                        });
                }
            }
        </script>
    </div>
</body></html>
"""

market_data_html = """
<!DOCTYPE html>
<html><head><title>Market Data - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans">
    <div class="max-w-5xl mx-auto p-6">
        <h1 class="text-3xl font-bold text-emerald-400 mb-6">📊 Live Market Data</h1>
        <p>Market Status: <strong>{{ market_status.status }}</strong></p>
        <p>Next Open: {{ market_status.next_open }}</p>
        <h2 class="text-xl font-semibold text-emerald-300 mt-6 mb-4">🚀 Top Market Movers</h2>
        <div class="overflow-x-auto">
            <table class="w-full border-collapse">
                <thead>
                    <tr class="bg-emerald-500/30">
                        <th class="p-3 text-left">Symbol</th>
                        <th class="p-3 text-left">Price</th>
                        <th class="p-3 text-left">Change</th>
                        <th class="p-3 text-left">% Change</th>
                    </tr>
                </thead>
                <tbody>
                    {% for mover in top_movers %}
                    <tr class="bg-gray-800/30">
                        <td class="p-3">{{ mover.symbol }}</td>
                        <td class="p-3">${{ "%.2f"|format(mover.price) }}</td>
                        <td class="p-3 {{ 'text-emerald-400' if mover.change >= 0 else 'text-red-400' }}">{{ "%.2f"|format(mover.change) }}</td>
                        <td class="p-3 {{ 'text-emerald-400' if mover.change_percent >= 0 else 'text-red-400' }}">{{ "%.2f"|format(mover.change_percent) }}%</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        <p class="mt-6">
            <a href="/" class="text-emerald-300 hover:underline">Home</a> | 
            <a href="/login" class="text-emerald-300 hover:underline">Login</a>
        </p>
    </div>
</body></html>
"""

mobile_demo_html = """
<!DOCTYPE html>
<html><head><title>Mobile Demo - ShadowStrike Options</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-gray-900 to-emerald-900 text-white font-sans flex items-center justify-center min-h-screen">
    <div class="max-w-md mx-auto bg-gray-800/50 p-8 rounded-2xl shadow-2xl text-center">
        <h1 class="text-3xl font-bold text-emerald-400 mb-6">📱 ShadowStrike Mobile Demo</h1>
        <p class="text-emerald-100 mb-6">Experience our mobile app with the same powerful features!</p>
        <div class="bg-emerald-500/10 p-6 rounded-lg mb-6">
            <p class="text-emerald-100">📲 Download the ShadowStrike app for iOS or Android to trade on-the-go.</p>
            <p class="text-emerald-100 mt-4">🚀 Full app coming soon!</p>
        </div>
        <a href="/login" class="block bg-emerald-500 text-white py-3 px-6 rounded-lg font-bold hover:bg-emerald-600">Back to Login</a>
    </div>
</body></html>
"""

# Create templates directory and write HTML files
try:
    os.makedirs("templates", exist_ok=True)
    
    templates = {
        "welcome.html": welcome_html,
        "login.html": login_html,
        "register.html": register_html,
        "reset_password.html": reset_password_html,
        "dashboard.html": dashboard_html,
        "subscribe.html": subscribe_html,
        "market_data.html": market_data_html,
        "mobile_demo.html": mobile_demo_html
    }
    
    for name, content in templates.items():
        with open(f"templates/{name}", "w", encoding='utf-8') as f:
            f.write(content)
            
    print("✅ Templates created successfully!")
    
except Exception as e:
    print(f"❌ Error creating templates: {e}")

# Main application runner
if __name__ == '__main__':
    try:
        # Get port from environment variable or default to 5000
        port = int(os.environ.get('PORT', 5000))
        
        # Create database tables
        with app.app_context():
            db.create_all()
            print("✅ Database tables created successfully!")
        
        print(f"🚀 Starting ShadowStrike Options server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        import traceback
        traceback.print_exc()
