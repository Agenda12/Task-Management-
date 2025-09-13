from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps
import secrets

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat()
        }

# Task model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(10), default='medium')
    status = db.Column(db.String(20), default='pending')
    due_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'status': self.status,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

    def is_overdue(self):
        if self.due_date and self.status != 'completed':
            return datetime.utcnow() > self.due_date
        return False

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        if '@' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        if password != confirm_password:
            errors.append('Passwords do not match.')

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')

        # Create new user
        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html')

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.created_at.desc()).all()
    
    # Calculate statistics
    total_tasks = len(tasks)
    completed_tasks = len([t for t in tasks if t.status == 'completed'])
    pending_tasks = len([t for t in tasks if t.status == 'pending'])
    in_progress_tasks = len([t for t in tasks if t.status == 'in_progress'])
    overdue_tasks = len([t for t in tasks if t.is_overdue()])

    stats = {
        'total': total_tasks,
        'completed': completed_tasks,
        'pending': pending_tasks,
        'in_progress': in_progress_tasks,
        'overdue': overdue_tasks
    }

    return render_template('dashboard.html', tasks=tasks, stats=stats, user=user)

# Create task route
@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        priority = request.form.get('priority', 'medium')
        due_date_str = request.form.get('due_date', '')
        
        if not title:
            flash('Task title is required.', 'error')
            return render_template('create_task.html')
        
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format.', 'error')
                return render_template('create_task.html')
        
        try:
            new_task = Task(
                title=title,
                description=description,
                priority=priority,
                due_date=due_date,
                user_id=session['user_id']
            )
            db.session.add(new_task)
            db.session.commit()
            flash('Task created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating task. Please try again.', 'error')
    
    return render_template('create_task.html')

# Edit task route
@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        task.title = request.form.get('title', '').strip()
        task.description = request.form.get('description', '').strip()
        task.priority = request.form.get('priority', 'medium')
        task.status = request.form.get('status', 'pending')
        due_date_str = request.form.get('due_date', '')
        
        if not task.title:
            flash('Task title is required.', 'error')
            return render_template('edit_task.html', task=task)
        
        if due_date_str:
            try:
                task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format.', 'error')
                return render_template('edit_task.html', task=task)
        else:
            task.due_date = None
        
        try:
            db.session.commit()
            flash('Task updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating task. Please try again.', 'error')
    
    return render_template('edit_task.html', task=task)

# Delete task route
@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        flash('Task not found.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting task. Please try again.', 'error')
    
    return redirect(url_for('dashboard'))

# API endpoints
@app.route('/api/tasks')
@login_required
def api_tasks():
    tasks = Task.query.filter_by(user_id=session['user_id']).all()
    return jsonify([task.to_dict() for task in tasks])

@app.route('/api/tasks/<int:task_id>/status', methods=['PUT'])
@login_required
def update_task_status(task_id):
    task = Task.query.filter_by(id=task_id, user_id=session['user_id']).first()
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    data = request.get_json()
    new_status = data.get('status')
    
    if new_status not in ['pending', 'in_progress', 'completed']:
        return jsonify({'error': 'Invalid status'}), 400
    
    try:
        task.status = new_status
        db.session.commit()
        return jsonify(task.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update task'}), 500

# Profile route
@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# Search tasks
@app.route('/search')
@login_required
def search_tasks():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('dashboard'))
    
    tasks = Task.query.filter_by(user_id=session['user_id']).filter(
        Task.title.contains(query) | Task.description.contains(query)
    ).order_by(Task.created_at.desc()).all()
    
    return render_template('search_results.html', tasks=tasks, query=query)

# Filter tasks by status
@app.route('/tasks/<status>')
@login_required
def filter_tasks(status):
    if status not in ['pending', 'in_progress', 'completed', 'overdue']:
        return redirect(url_for('dashboard'))
    
    tasks = Task.query.filter_by(user_id=session['user_id'])
    
    if status == 'overdue':
        tasks = [t for t in tasks.all() if t.is_overdue()]
    else:
        tasks = tasks.filter_by(status=status).all()
    
    return render_template('filtered_tasks.html', tasks=tasks, status=status)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Database initialization function
def init_db():
    """Initialize the database with tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

# Sample data function
def create_sample_data():
    """Create sample user and tasks for testing."""
    with app.app_context():
        # Check if sample user already exists
        if User.query.filter_by(username='demo').first():
            print("Sample data already exists!")
            return
        
        # Create sample user
        demo_user = User(username='demo', email='demo@example.com')
        demo_user.set_password('password123')
        db.session.add(demo_user)
        db.session.commit()
        
        # Create sample tasks
        sample_tasks = [
            Task(
                title='Complete project proposal',
                description='Write and submit the Q4 project proposal',
                priority='high',
                status='in_progress',
                due_date=datetime.utcnow() + timedelta(days=3),
                user_id=demo_user.id
            ),
            Task(
                title='Review code changes',
                description='Review pull requests from team members',
                priority='medium',
                status='pending',
                due_date=datetime.utcnow() + timedelta(days=1),
                user_id=demo_user.id
            ),
            Task(
                title='Update documentation',
                description='Update API documentation with latest changes',
                priority='low',
                status='completed',
                user_id=demo_user.id
            ),
            Task(
                title='Team meeting preparation',
                description='Prepare agenda and materials for weekly team meeting',
                priority='medium',
                status='pending',
                due_date=datetime.utcnow() + timedelta(days=2),
                user_id=demo_user.id
            )
        ]
        
        for task in sample_tasks:
            db.session.add(task)
        
        db.session.commit()
        print("Sample data created successfully!")
        print("Demo user credentials: username='demo', password='password123'")

# Main execution
if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Create sample data (optional)
    create_sample_data()
    
    # Run the application
    print("Starting Task Manager Application...")
    print("Access the application at: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)