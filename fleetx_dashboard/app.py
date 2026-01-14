#!/usr/bin/env python3
"""
FleetX Dashboard - Flask Application
Vehicle route playback, geofencing, and decision-making stats
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash, make_response
import sqlite3
import json
from datetime import datetime, timedelta
from functools import wraps
import os
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fleetx-dashboard-secret'

# Database path - adjust if needed
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fleetx_data.db')
GEOFENCE_DB = os.path.join(os.path.dirname(__file__), 'geofences.db')
USERS_DB = os.path.join(os.path.dirname(__file__), 'users.db')


def get_db_connection():
    """Get connection to the main FleetX database"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_geofence_db():
    """Get connection to geofence database"""
    conn = sqlite3.connect(GEOFENCE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def get_users_db():
    """Get connection to users database"""
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_geofence_db():
    """Initialize geofence database"""
    conn = get_geofence_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS geofences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'polygon',
            coordinates TEXT NOT NULL,
            color TEXT DEFAULT '#3b82f6',
            alert_on_enter INTEGER DEFAULT 1,
            alert_on_exit INTEGER DEFAULT 1,
            active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def init_users_db():
    """Initialize users database with schema"""
    conn = get_users_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            must_reset_password INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create RBAC table for vehicle-level access control
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vehicle_access_control (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vehicle_number TEXT NOT NULL,
            dispatch_access INTEGER DEFAULT 0,
            geofence_access INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, vehicle_number)
        )
    ''')

    # Create audit_logs table for tracking user activity
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            event_type TEXT NOT NULL,
            page_route TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    # Create index for faster queries on common filters
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type)
    ''')

    conn.commit()
    conn.close()


init_geofence_db()
init_users_db()


# ============== AUDIT LOGGING ==============

def log_audit_event(event_type, page_route=None, user_id=None, username=None):
    """
    Log an audit event to the database

    Args:
        event_type: Type of event ('login', 'logout', 'page_access')
        page_route: The route/page accessed (optional, null for login/logout)
        user_id: User ID (optional, will try to get from session)
        username: Username (optional, will try to get from session)
    """
    try:
        # Get user info from session if not provided
        if user_id is None:
            user_id = session.get('user_id')
        if username is None:
            username = session.get('username')

        # Get IP address
        if request.environ.get('HTTP_X_FORWARDED_FOR'):
            ip_address = request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
        else:
            ip_address = request.environ.get('REMOTE_ADDR', 'Unknown')

        # Get user agent
        user_agent = request.headers.get('User-Agent', '')[:255]  # Limit length

        # Insert audit log
        conn = get_users_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (user_id, username, event_type, page_route, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, event_type, page_route, ip_address, user_agent))
        conn.commit()
        conn.close()
    except Exception as e:
        # Don't let audit logging break the app
        print(f"Audit logging error: {e}")


# ============== AUTHENTICATION ==============

def get_user_nav_permissions(user_id):
    """
    Get aggregated navigation permissions for a user.
    Returns which nav items the user should see based on their RBAC settings.
    Admin users get full access.
    """
    conn = get_users_db()
    cursor = conn.cursor()

    # Check if user is admin
    cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if user and user['role'] == 'admin':
        conn.close()
        return {
            'vehicles': True,
            'dispatch': True,
            'geofence': True
        }

    # For regular users, aggregate permissions across all vehicles
    cursor.execute('''
        SELECT
            MAX(dispatch_access) as has_dispatch,
            MAX(geofence_access) as has_geofence
        FROM vehicle_access_control
        WHERE user_id = ?
    ''', (user_id,))

    result = cursor.fetchone()
    conn.close()

    if result:
        has_dispatch = bool(result['has_dispatch']) if result['has_dispatch'] else False
        has_geofence = bool(result['has_geofence']) if result['has_geofence'] else False
    else:
        has_dispatch = False
        has_geofence = False

    # Vehicles nav is shown if user has ANY permission (dispatch or geofence)
    # This ensures they can at least see the vehicles they have access to
    has_vehicles = has_dispatch or has_geofence

    return {
        'vehicles': has_vehicles,
        'dispatch': has_dispatch,
        'geofence': has_geofence
    }


def login_required(f):
    """Decorator to protect routes that require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to protect routes that require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def no_cache(f):
    """Decorator to prevent browser caching of protected pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return decorated_function


def dispatch_access_required(f):
    """Decorator to protect dispatch-related routes based on RBAC"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # Admin users have full access
        if session.get('role') == 'admin':
            return f(*args, **kwargs)

        # Check if user has dispatch access to any vehicle
        nav_permissions = get_user_nav_permissions(session.get('user_id'))
        if not nav_permissions.get('dispatch'):
            return jsonify({'error': 'Access denied. Dispatch permission required.'}), 403

        return f(*args, **kwargs)
    return decorated_function


def geofence_access_required(f):
    """Decorator to protect geofence-related routes based on RBAC"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # Admin users have full access
        if session.get('role') == 'admin':
            return f(*args, **kwargs)

        # Check if user has geofence access to any vehicle
        nav_permissions = get_user_nav_permissions(session.get('user_id'))
        if not nav_permissions.get('geofence'):
            return jsonify({'error': 'Access denied. Geofence permission required.'}), 403

        return f(*args, **kwargs)
    return decorated_function


# ============== PAGES ==============

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler"""
    if request.method == 'POST':
        identifier = request.form.get('username')  # Can be user ID, username, or email
        password = request.form.get('password')

        # Check database users - accept ID, username (name), or email
        conn = get_users_db()
        cursor = conn.cursor()

        # Try to match by ID (if identifier is numeric), username, or email
        if identifier.isdigit():
            # If input is numeric, try ID first
            cursor.execute('SELECT * FROM users WHERE id = ? OR name = ? OR email = ?',
                         (int(identifier), identifier, identifier))
        else:
            # If not numeric, try username or email
            cursor.execute('SELECT * FROM users WHERE name = ? OR email = ?',
                         (identifier, identifier))

        user = cursor.fetchone()
        conn.close()

        if user and user['password'] == password:  # In production, use hashed passwords
            # Check if user must reset password
            if user['must_reset_password']:
                session['temp_user_id'] = user['id']
                return redirect(url_for('reset_password'))

            session['logged_in'] = True
            session['username'] = user['name']
            session['user_id'] = user['id']
            session['role'] = user['role']

            # Load and store RBAC navigation permissions
            session['nav_permissions'] = get_user_nav_permissions(user['id'])

            # Log successful login
            log_audit_event('login', user_id=user['id'], username=user['name'])

            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    # If already logged in, redirect to dashboard
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@no_cache
def logout():
    """Logout handler - clears session and prevents caching"""
    # Log logout before clearing session
    log_audit_event('logout')

    session.clear()
    response = make_response(redirect(url_for('login')))
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response


@app.route('/')
@login_required
@no_cache
def dashboard():
    """Main dashboard page - requires authentication and prevents caching"""
    # Refresh RBAC permissions on each dashboard load (reflects admin changes immediately)
    nav_permissions = get_user_nav_permissions(session.get('user_id'))
    session['nav_permissions'] = nav_permissions

    # Check if user has ANY permissions (admin users always have access)
    if session.get('role') != 'admin':
        has_any_permission = any([
            nav_permissions.get('vehicles'),
            nav_permissions.get('dispatch'),
            nav_permissions.get('geofence')
        ])
        if not has_any_permission:
            return redirect(url_for('no_access'))

    # Log page access
    log_audit_event('page_access', page_route='Dashboard')

    return render_template('dashboard.html', nav_permissions=nav_permissions)


@app.route('/no-access')
@login_required
@no_cache
def no_access():
    """No access page for users with zero permissions"""
    # If user is admin or has permissions, redirect to dashboard
    if session.get('role') == 'admin':
        return redirect(url_for('dashboard'))

    nav_permissions = get_user_nav_permissions(session.get('user_id'))
    has_any_permission = any([
        nav_permissions.get('vehicles'),
        nav_permissions.get('dispatch'),
        nav_permissions.get('geofence')
    ])

    if has_any_permission:
        return redirect(url_for('dashboard'))

    # Log the access attempt
    log_audit_event('page_access', page_route='No Access Page')

    return render_template('no_access.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """Force password reset for first-time login"""
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or len(new_password) < 6:
            return render_template('reset_password.html', error='Password must be at least 6 characters')

        if new_password != confirm_password:
            return render_template('reset_password.html', error='Passwords do not match')

        # Update password and clear reset flag
        conn = get_users_db()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET password = ?, must_reset_password = 0, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_password, session['temp_user_id']))
        conn.commit()

        # Get user info for session
        cursor.execute('SELECT * FROM users WHERE id = ?', (session['temp_user_id'],))
        user = cursor.fetchone()
        conn.close()

        # Log user in
        session.pop('temp_user_id', None)
        session['logged_in'] = True
        session['username'] = user['name']
        session['user_id'] = user['id']
        session['role'] = user['role']

        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('reset_password.html')


# ============== ADMIN ROUTES ==============

@app.route('/admin')
@admin_required
@no_cache
def admin_dashboard():
    """Admin dashboard page - requires admin role"""
    # Log page access
    log_audit_event('page_access', page_route='Admin Dashboard')

    return render_template('admin.html')


@app.route('/admin/users')
@admin_required
@no_cache
def manage_users():
    """Manage users page - requires admin role"""
    # Log page access
    log_audit_event('page_access', page_route='Admin - Manage Users')

    conn = get_users_db()
    cursor = conn.cursor()
    # Order by role (admin first), then by created_at DESC
    cursor.execute('SELECT * FROM users ORDER BY CASE WHEN role = "admin" THEN 0 ELSE 1 END, created_at DESC')
    users_raw = cursor.fetchall()
    conn.close()

    # Add display IDs (sequential starting from 1)
    users = []
    for index, user in enumerate(users_raw, start=1):
        user_dict = dict(user)
        user_dict['display_id'] = index
        users.append(user_dict)

    return render_template('manage_users.html', users=users)


@app.route('/admin/users/add', methods=['POST'])
@admin_required
def add_user():
    """Create a new user"""
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not name or not email or not password:
        flash('All fields are required', 'error')
        return redirect(url_for('manage_users'))

    if len(password) < 6:
        flash('Password must be at least 6 characters', 'error')
        return redirect(url_for('manage_users'))

    conn = get_users_db()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO users (name, email, password, role, must_reset_password)
            VALUES (?, ?, ?, ?, 1)
        ''', (name, email, password, role))
        conn.commit()
        flash(f'User {name} created successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists', 'error')
    finally:
        conn.close()

    return redirect(url_for('manage_users'))


@app.route('/admin/users/<int:user_id>/update', methods=['POST'])
@admin_required
def update_user(user_id):
    """Update an existing user"""
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not name or not email:
        flash('Name and email are required', 'error')
        return redirect(url_for('manage_users'))

    conn = get_users_db()
    cursor = conn.cursor()

    try:
        if password:
            # Update with new password and force reset
            if len(password) < 6:
                flash('Password must be at least 6 characters', 'error')
                conn.close()
                return redirect(url_for('manage_users'))

            cursor.execute('''
                UPDATE users SET name = ?, email = ?, password = ?, role = ?,
                                 must_reset_password = 1, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (name, email, password, role, user_id))
        else:
            # Update without changing password
            cursor.execute('''
                UPDATE users SET name = ?, email = ?, role = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (name, email, role, user_id))

        conn.commit()
        flash('User updated successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists', 'error')
    finally:
        conn.close()

    return redirect(url_for('manage_users'))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user"""
    conn = get_users_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully', 'success')
    return redirect(url_for('manage_users'))


# ============== RBAC ROUTES ==============

@app.route('/admin/rbac')
@admin_required
@no_cache
def rbac_dashboard():
    """RBAC vehicle access control page"""
    # Log page access
    log_audit_event('page_access', page_route='Admin - RBAC')

    return render_template('rbac.html')


@app.route('/api/rbac/vehicles')
@admin_required
def get_rbac_vehicles():
    """Get distinct vehicles from fleetx_data.db"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT vehicle_number, vehicle_name
        FROM vehicle_location_history
        WHERE vehicle_number IS NOT NULL AND vehicle_number != ''
        ORDER BY vehicle_number
    ''')
    vehicles = [{'number': row[0], 'name': row[1]} for row in cursor.fetchall()]
    conn.close()
    return jsonify(vehicles)


@app.route('/api/rbac/users')
@admin_required
def get_rbac_users():
    """Get all users for RBAC dropdown"""
    conn = get_users_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, email, role FROM users WHERE role != \"admin\" ORDER BY name')
    users_raw = cursor.fetchall()
    conn.close()

    # Add display IDs (sequential starting from 1)
    users = []
    for index, row in enumerate(users_raw, start=1):
        users.append({
            'id': row[0],
            'display_id': index,
            'name': row[1],
            'email': row[2],
            'role': row[3]
        })

    return jsonify(users)


@app.route('/api/rbac/permissions/<int:user_id>')
@admin_required
def get_user_permissions(user_id):
    """Get vehicle access permissions for a specific user"""
    conn = get_users_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT vehicle_number, dispatch_access, geofence_access
        FROM vehicle_access_control
        WHERE user_id = ?
    ''', (user_id,))

    permissions = {}
    for row in cursor.fetchall():
        permissions[row[0]] = {
            'dispatch': bool(row[1]),
            'geofence': bool(row[2])
        }
    conn.close()
    return jsonify(permissions)


@app.route('/api/rbac/permissions', methods=['POST'])
@admin_required
def save_permissions():
    """Save vehicle access permissions for a user"""
    data = request.json
    user_id = data.get('user_id')
    vehicle_number = data.get('vehicle_number')
    dispatch_access = data.get('dispatch_access', False)
    geofence_access = data.get('geofence_access', False)

    if not user_id or not vehicle_number:
        return jsonify({'error': 'Missing required fields'}), 400

    conn = get_users_db()
    cursor = conn.cursor()

    try:
        # Use INSERT OR REPLACE to handle both new and existing records
        cursor.execute('''
            INSERT OR REPLACE INTO vehicle_access_control
            (user_id, vehicle_number, dispatch_access, geofence_access, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, vehicle_number, int(dispatch_access), int(geofence_access)))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


# ============== AUDIT LOGS ROUTES ==============

@app.route('/admin/audit-logs')
@admin_required
@no_cache
def audit_logs():
    """Audit logs page - requires admin role"""
    # Log page access
    log_audit_event('page_access', page_route='Admin - Audit Logs')

    # Get filter parameters
    event_type_filter = request.args.get('event_type', 'all')
    user_id_filter = request.args.get('user_id', 'all')
    limit = request.args.get('limit', 100, type=int)

    conn = get_users_db()
    cursor = conn.cursor()

    # Build query based on filters
    query = 'SELECT * FROM audit_logs WHERE 1=1'
    params = []

    if event_type_filter != 'all':
        query += ' AND event_type = ?'
        params.append(event_type_filter)

    if user_id_filter != 'all':
        query += ' AND user_id = ?'
        params.append(int(user_id_filter))

    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)
    logs_raw = cursor.fetchall()

    # Get all users for filter dropdown
    cursor.execute('SELECT id, name FROM users ORDER BY name')
    users_raw = cursor.fetchall()

    # Add display IDs to users
    users = []
    for index, user_row in enumerate(users_raw, start=1):
        users.append({
            'id': user_row[0],
            'display_id': index,
            'name': user_row[1]
        })

    conn.close()

    # Convert timestamps to IST
    ist = pytz.timezone('Asia/Kolkata')
    logs = []
    for log in logs_raw:
        log_dict = dict(log)
        if log_dict['timestamp']:
            # Parse the UTC timestamp from database
            utc_time = datetime.strptime(log_dict['timestamp'], '%Y-%m-%d %H:%M:%S')
            utc_time = pytz.utc.localize(utc_time)
            # Convert to IST
            ist_time = utc_time.astimezone(ist)
            log_dict['timestamp'] = ist_time.strftime('%Y-%m-%d %I:%M:%S %p IST')
        logs.append(log_dict)

    return render_template('audit_logs.html',
                         logs=logs,
                         users=users,
                         event_type_filter=event_type_filter,
                         user_id_filter=user_id_filter,
                         limit=limit)


# ============== VEHICLE API ==============

@app.route('/api/vehicles')
def get_vehicles():
    """Get list of all vehicles with latest position"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT vehicle_id, vehicle_number, vehicle_name,
               vehicle_make, vehicle_model, driver_name
        FROM vehicle_location_history
        GROUP BY vehicle_id
    ''')

    vehicles = []
    for row in cursor.fetchall():
        # Get latest position for each vehicle
        cursor.execute('''
            SELECT latitude, longitude, speed, status, address,
                   timestamp, total_odometer, current_odometer
            FROM vehicle_location_history
            WHERE vehicle_id = ?
            ORDER BY fetch_timestamp DESC
            LIMIT 1
        ''', (row['vehicle_id'],))

        latest = cursor.fetchone()
        vehicles.append({
            'id': row['vehicle_id'],
            'number': row['vehicle_number'],
            'name': row['vehicle_name'],
            'make': row['vehicle_make'],
            'model': row['vehicle_model'],
            'driver': row['driver_name'],
            'latitude': latest['latitude'] if latest else None,
            'longitude': latest['longitude'] if latest else None,
            'speed': latest['speed'] if latest else 0,
            'status': latest['status'] if latest else 'unknown',
            'address': latest['address'] if latest else '',
            'lastUpdate': latest['timestamp'] if latest else None,
            'totalOdometer': latest['total_odometer'] if latest else 0,
            'currentOdometer': latest['current_odometer'] if latest else 0
        })

    conn.close()
    return jsonify(vehicles)


@app.route('/api/vehicles/<int:vehicle_id>/stats')
def get_vehicle_stats(vehicle_id):
    """Get comprehensive stats for a vehicle"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Basic info
    cursor.execute('''
        SELECT vehicle_number, vehicle_name, vehicle_make, vehicle_model,
               driver_name, vehicle_year
        FROM vehicle_location_history
        WHERE vehicle_id = ?
        ORDER BY fetch_timestamp DESC
        LIMIT 1
    ''', (vehicle_id,))

    info = cursor.fetchone()
    if not info:
        conn.close()
        return jsonify({'error': 'Vehicle not found'}), 404

    # Speed statistics
    cursor.execute('''
        SELECT
            AVG(speed) as avg_speed,
            MAX(speed) as max_speed,
            MIN(CASE WHEN speed > 0 THEN speed END) as min_moving_speed
        FROM vehicle_location_history
        WHERE vehicle_id = ?
    ''', (vehicle_id,))
    speed_stats = cursor.fetchone()

    # Odometer range (distance traveled in tracked period)
    cursor.execute('''
        SELECT
            MIN(total_odometer) as start_odometer,
            MAX(total_odometer) as end_odometer
        FROM vehicle_location_history
        WHERE vehicle_id = ? AND total_odometer > 0
    ''', (vehicle_id,))
    odo_stats = cursor.fetchone()

    # Status distribution
    cursor.execute('''
        SELECT status, COUNT(*) as count
        FROM vehicle_location_history
        WHERE vehicle_id = ?
        GROUP BY status
    ''', (vehicle_id,))
    status_dist = {row['status']: row['count'] for row in cursor.fetchall()}

    # Activity by hour (for dispatch optimization)
    cursor.execute('''
        SELECT
            CAST(strftime('%H', fetch_timestamp) AS INTEGER) as hour,
            AVG(speed) as avg_speed,
            COUNT(*) as readings
        FROM vehicle_location_history
        WHERE vehicle_id = ?
        GROUP BY hour
        ORDER BY hour
    ''', (vehicle_id,))
    hourly_activity = [{'hour': row['hour'], 'avgSpeed': row['avg_speed'],
                        'readings': row['readings']} for row in cursor.fetchall()]

    # Recent trips count (based on status changes)
    cursor.execute('''
        SELECT COUNT(*) as trip_count
        FROM (
            SELECT status, LAG(status) OVER (ORDER BY fetch_timestamp) as prev_status
            FROM vehicle_location_history
            WHERE vehicle_id = ?
        )
        WHERE status = 'RUNNING' AND prev_status != 'RUNNING'
    ''', (vehicle_id,))
    trip_result = cursor.fetchone()

    # Total tracked time
    cursor.execute('''
        SELECT
            MIN(fetch_timestamp) as first_seen,
            MAX(fetch_timestamp) as last_seen,
            COUNT(*) as total_readings
        FROM vehicle_location_history
        WHERE vehicle_id = ?
    ''', (vehicle_id,))
    time_stats = cursor.fetchone()

    conn.close()

    distance_traveled = 0
    if odo_stats['end_odometer'] and odo_stats['start_odometer']:
        distance_traveled = odo_stats['end_odometer'] - odo_stats['start_odometer']

    return jsonify({
        'vehicle': {
            'id': vehicle_id,
            'number': info['vehicle_number'],
            'name': info['vehicle_name'],
            'make': info['vehicle_make'],
            'model': info['vehicle_model'],
            'driver': info['driver_name'],
            'year': info['vehicle_year']
        },
        'speed': {
            'average': round(speed_stats['avg_speed'] or 0, 1),
            'max': round(speed_stats['max_speed'] or 0, 1),
            'minMoving': round(speed_stats['min_moving_speed'] or 0, 1)
        },
        'distance': {
            'traveled': round(distance_traveled, 2),
            'currentOdometer': odo_stats['end_odometer'] or 0
        },
        'statusDistribution': status_dist,
        'hourlyActivity': hourly_activity,
        'tripCount': trip_result['trip_count'] if trip_result else 0,
        'tracking': {
            'firstSeen': time_stats['first_seen'],
            'lastSeen': time_stats['last_seen'],
            'totalReadings': time_stats['total_readings']
        }
    })


# ============== ROUTE PLAYBACK API ==============

@app.route('/api/vehicles/<int:vehicle_id>/route')
def get_vehicle_route(vehicle_id):
    """Get route history for playback"""
    start_time = request.args.get('start')
    end_time = request.args.get('end')
    limit = request.args.get('limit', 1000, type=int)

    conn = get_db_connection()
    cursor = conn.cursor()

    query = '''
        SELECT latitude, longitude, speed, status, address,
               timestamp, fetch_timestamp, course, total_odometer
        FROM vehicle_location_history
        WHERE vehicle_id = ?
    '''
    params = [vehicle_id]

    if start_time:
        query += ' AND fetch_timestamp >= ?'
        params.append(start_time)
    if end_time:
        query += ' AND fetch_timestamp <= ?'
        params.append(end_time)

    query += ' ORDER BY fetch_timestamp ASC LIMIT ?'
    params.append(limit)

    cursor.execute(query, params)

    route = []
    for row in cursor.fetchall():
        route.append({
            'lat': row['latitude'],
            'lng': row['longitude'],
            'speed': row['speed'],
            'status': row['status'],
            'address': row['address'],
            'timestamp': row['timestamp'],
            'fetchTime': row['fetch_timestamp'],
            'course': row['course'],
            'odometer': row['total_odometer']
        })

    conn.close()
    return jsonify(route)


@app.route('/api/vehicles/<int:vehicle_id>/route/dates')
def get_available_dates(vehicle_id):
    """Get available dates for route playback"""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT DATE(fetch_timestamp) as date,
               COUNT(*) as points
        FROM vehicle_location_history
        WHERE vehicle_id = ?
        GROUP BY DATE(fetch_timestamp)
        ORDER BY date DESC
    ''', (vehicle_id,))

    dates = [{'date': row['date'], 'points': row['points']} for row in cursor.fetchall()]
    conn.close()
    return jsonify(dates)


# ============== GEOFENCING API ==============

@app.route('/api/geofences', methods=['GET'])
@geofence_access_required
def get_geofences():
    """Get all geofences or filter by vehicle"""
    vehicle_id = request.args.get('vehicle_id', type=int)

    conn = get_geofence_db()
    cursor = conn.cursor()

    if vehicle_id:
        cursor.execute('SELECT * FROM geofences WHERE vehicle_id = ? OR vehicle_id IS NULL',
                       (vehicle_id,))
    else:
        cursor.execute('SELECT * FROM geofences')

    geofences = []
    for row in cursor.fetchall():
        geofences.append({
            'id': row['id'],
            'vehicleId': row['vehicle_id'],
            'name': row['name'],
            'type': row['type'],
            'coordinates': json.loads(row['coordinates']),
            'color': row['color'],
            'alertOnEnter': bool(row['alert_on_enter']),
            'alertOnExit': bool(row['alert_on_exit']),
            'active': bool(row['active']),
            'createdAt': row['created_at'],
            'updatedAt': row['updated_at']
        })

    conn.close()
    return jsonify(geofences)


@app.route('/api/geofences', methods=['POST'])
@geofence_access_required
def create_geofence():
    """Create a new geofence"""
    data = request.json

    conn = get_geofence_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO geofences (vehicle_id, name, type, coordinates, color,
                              alert_on_enter, alert_on_exit, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('vehicleId'),
        data.get('name', 'Unnamed Geofence'),
        data.get('type', 'polygon'),
        json.dumps(data.get('coordinates', [])),
        data.get('color', '#3b82f6'),
        1 if data.get('alertOnEnter', True) else 0,
        1 if data.get('alertOnExit', True) else 0,
        1 if data.get('active', True) else 0
    ))

    geofence_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({'id': geofence_id, 'message': 'Geofence created'}), 201


@app.route('/api/geofences/<int:geofence_id>', methods=['PUT'])
@geofence_access_required
def update_geofence(geofence_id):
    """Update a geofence"""
    data = request.json

    conn = get_geofence_db()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE geofences SET
            vehicle_id = ?,
            name = ?,
            type = ?,
            coordinates = ?,
            color = ?,
            alert_on_enter = ?,
            alert_on_exit = ?,
            active = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (
        data.get('vehicleId'),
        data.get('name'),
        data.get('type'),
        json.dumps(data.get('coordinates', [])),
        data.get('color'),
        1 if data.get('alertOnEnter', True) else 0,
        1 if data.get('alertOnExit', True) else 0,
        1 if data.get('active', True) else 0,
        geofence_id
    ))

    conn.commit()
    conn.close()

    return jsonify({'message': 'Geofence updated'})


@app.route('/api/geofences/<int:geofence_id>', methods=['DELETE'])
@geofence_access_required
def delete_geofence(geofence_id):
    """Delete a geofence"""
    conn = get_geofence_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM geofences WHERE id = ?', (geofence_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Geofence deleted'})


# ============== DISPATCH DECISION API ==============

@app.route('/api/dispatch/rankings')
@dispatch_access_required
def get_dispatch_rankings():
    """Get vehicle rankings for dispatch decisions"""
    caller_lat = request.args.get('lat', type=float)
    caller_lng = request.args.get('lng', type=float)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get all vehicles with their latest positions
    cursor.execute('''
        SELECT v.vehicle_id, v.vehicle_number, v.vehicle_name, v.driver_name,
               v.latitude, v.longitude, v.speed, v.status, v.address
        FROM vehicle_location_history v
        INNER JOIN (
            SELECT vehicle_id, MAX(fetch_timestamp) as max_time
            FROM vehicle_location_history
            GROUP BY vehicle_id
        ) latest ON v.vehicle_id = latest.vehicle_id
                 AND v.fetch_timestamp = latest.max_time
    ''')

    vehicles = []
    for row in cursor.fetchall():
        vehicle = {
            'id': row['vehicle_id'],
            'number': row['vehicle_number'],
            'name': row['vehicle_name'],
            'driver': row['driver_name'],
            'latitude': row['latitude'],
            'longitude': row['longitude'],
            'speed': row['speed'],
            'status': row['status'],
            'address': row['address'],
            'distance': None,
            'score': 100  # Base score
        }

        # Calculate distance if caller location provided
        if caller_lat and caller_lng and row['latitude'] and row['longitude']:
            # Haversine formula approximation (km)
            import math
            lat1, lon1 = math.radians(caller_lat), math.radians(caller_lng)
            lat2, lon2 = math.radians(row['latitude']), math.radians(row['longitude'])

            dlat = lat2 - lat1
            dlon = lon2 - lon1

            a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
            c = 2 * math.asin(math.sqrt(a))
            vehicle['distance'] = round(6371 * c, 2)  # Earth radius in km

            # Adjust score based on distance (closer = higher score)
            vehicle['score'] -= min(vehicle['distance'] * 2, 50)

        # Adjust score based on status
        if row['status'] == 'IDLE':
            vehicle['score'] += 20  # Prefer idle vehicles
        elif row['status'] == 'RUNNING':
            vehicle['score'] -= 10  # Slightly lower for running
        elif row['status'] == 'STOPPED':
            vehicle['score'] += 10

        # Get utilization stats for this vehicle
        cursor.execute('''
            SELECT
                COUNT(*) as total_readings,
                SUM(CASE WHEN status = 'RUNNING' THEN 1 ELSE 0 END) as running_count
            FROM vehicle_location_history
            WHERE vehicle_id = ?
            AND fetch_timestamp > datetime('now', '-24 hours')
        ''', (row['vehicle_id'],))

        util = cursor.fetchone()
        if util and util['total_readings'] > 0:
            utilization = (util['running_count'] / util['total_readings']) * 100
            vehicle['utilization24h'] = round(utilization, 1)
            # Prefer less utilized vehicles
            vehicle['score'] -= utilization * 0.3
        else:
            vehicle['utilization24h'] = 0

        vehicle['score'] = round(max(0, vehicle['score']), 1)
        vehicles.append(vehicle)

    # Sort by score descending
    vehicles.sort(key=lambda x: x['score'], reverse=True)

    conn.close()
    return jsonify(vehicles)


@app.route('/api/stats/overview')
def get_overview_stats():
    """Get fleet overview statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total vehicles
    cursor.execute('SELECT COUNT(DISTINCT vehicle_id) as count FROM vehicle_location_history')
    total_vehicles = cursor.fetchone()['count']

    # Current status distribution
    cursor.execute('''
        SELECT v.status, COUNT(*) as count
        FROM vehicle_location_history v
        INNER JOIN (
            SELECT vehicle_id, MAX(fetch_timestamp) as max_time
            FROM vehicle_location_history
            GROUP BY vehicle_id
        ) latest ON v.vehicle_id = latest.vehicle_id
                 AND v.fetch_timestamp = latest.max_time
        GROUP BY v.status
    ''')
    status_counts = {row['status']: row['count'] for row in cursor.fetchall()}

    # Average speed of moving vehicles
    cursor.execute('''
        SELECT AVG(v.speed) as avg_speed
        FROM vehicle_location_history v
        INNER JOIN (
            SELECT vehicle_id, MAX(fetch_timestamp) as max_time
            FROM vehicle_location_history
            GROUP BY vehicle_id
        ) latest ON v.vehicle_id = latest.vehicle_id
                 AND v.fetch_timestamp = latest.max_time
        WHERE v.speed > 0
    ''')
    avg_speed = cursor.fetchone()['avg_speed'] or 0

    # Total distance tracked today
    cursor.execute('''
        SELECT SUM(max_odo - min_odo) as total_distance
        FROM (
            SELECT vehicle_id,
                   MAX(total_odometer) as max_odo,
                   MIN(total_odometer) as min_odo
            FROM vehicle_location_history
            WHERE DATE(fetch_timestamp) = DATE('now')
            AND total_odometer > 0
            GROUP BY vehicle_id
        )
    ''')
    total_distance = cursor.fetchone()['total_distance'] or 0

    conn.close()

    return jsonify({
        'totalVehicles': total_vehicles,
        'statusCounts': status_counts,
        'averageSpeed': round(avg_speed, 1),
        'totalDistanceToday': round(total_distance, 2)
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
