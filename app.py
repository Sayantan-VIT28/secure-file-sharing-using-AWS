from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_session import Session 
import boto3
from botocore.config import Config
import os
import uuid
import subprocess
import random
import string
import datetime
from werkzeug.utils import secure_filename
from passlib.hash import pbkdf2_sha256
from io import BytesIO
import zipfile
import tempfile
from boto3.dynamodb.conditions import Attr, Key
import time
import secrets
import re
import logging
import shutil
import botocore
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# AWS Configuration
AWS_REGION = 'ap-south-1'#your region
s3_client = boto3.client('s3', region_name=AWS_REGION, config=Config(s3={'addressing_style': 'virtual'}))
ses_client = boto3.client('ses', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)

# SES constant sender for OTP/MFA
SES_CONSTANT_SENDER = 'your-aws-ses-verified-email-address'

# DynamoDB tables
users_table = dynamodb.Table('UsersTable')
shares_table = dynamodb.Table('SharesTable')
bucket_requests_table = dynamodb.Table('RequestsTable')
audit_logs_table = dynamodb.Table('LogsTable')


# AES path
AES_EXE_PATH = os.getenv('AES_EXE_PATH', os.path.join(os.getcwd(), 'aes_file.exe'))

# Configurable OTP expiration
OTP_EXPIRATION_SECONDS = int(os.getenv('OTP_EXPIRATION_SECONDS', 600))

# File size limit
MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
TOTAL_STORAGE_MB = 5 * 1024  # 5GB total storage

# Configure Flask-Session 
app.config.update(
    SESSION_TYPE='filesystem',  
    SESSION_FILE_DIR=os.path.join(tempfile.gettempdir(), 'secure_sessions'),
    SESSION_COOKIE_NAME='generic_session_cookie',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True
)
Session(app)  # Initialize Flask-Session

# Function to clear session data
def clear_session_data():
    try:
        session_dir = app.config['SESSION_FILE_DIR']
        if os.path.exists(session_dir):
            shutil.rmtree(session_dir, ignore_errors=True)
        logger.info("Cleared session data")
    except Exception as e:
        logger.error(f"Failed to clear session data: {str(e)}")

# Function to reset DynamoDB tables (optional, use with caution)
def reset_dynamodb_tables():
    try:
        # Reset Users table
        response = users_table.scan()
        for item in response.get('Items', []):
            users_table.delete_item(Key={'email': item['email']})
        
        # Reset Shares table
        response = shares_table.scan()
        for item in response.get('Items', []):
            shares_table.delete_item(Key={'share_id': item['share_id']})
        
        # Reset Bucket Requests table
        response = bucket_requests_table.scan()
        for item in response.get('Items', []):
            bucket_requests_table.delete_item(Key={'request_id': item['request_id']})
        
        # Reset SessionsTable table (if it exists)
        try:
            sessions_table = dynamodb.Table('SessionsTable')
            response = sessions_table.scan()
            for item in response.get('Items', []):
                sessions_table.delete_item(Key={'id': item['id']})
            logger.info("Reset SessionsTable table")
        except Exception as sessions_error:
            logger.warning(f"SessionsTable table not found or error clearing: {sessions_error}")
        
        logger.info("Reset DynamoDB tables: UsersTable, SharesTable, RequestsTable, AppSessions")
    except Exception as e:
        logger.error(f"Failed to reset DynamoDB tables: {str(e)}")
        raise

# Password utility
def is_strong_password(pw):
    return (
        len(pw) >= 8 and
        any(c.isupper() for c in pw) and
        any(c.islower() for c in pw) and                                                                
        any(c.isdigit() for c in pw) and
        any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in pw)
    )

# Generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send MFA email
def send_mfa_email(recipient_email, otp):
    try:
        ses_client.send_email(
            Source=SES_CONSTANT_SENDER,
            Destination={'ToAddresses': [recipient_email]},
            Message={
                'Subject': {'Data': 'Your MFA OTP'},
                'Body': {'Text': {'Data': f'Your OTP is: {otp}'}}
            }
        )
        logger.info(f"MFA email sent to {recipient_email}")
    except Exception as e:
        logger.error(f"Failed to send MFA email to {recipient_email}: {str(e)}")
        raise Exception("Failed to send MFA email. Please check SES configuration.")

# Create user S3 bucket
def create_user_bucket(username):
    bucket_name = f"{username.lower()}-{uuid.uuid4().hex[:6]}"
    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
        )
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        cors_config = {
            'CORSRules': [
                {
                    'AllowedHeaders': ['*'],
                    'AllowedMethods': ['GET', 'PUT', 'POST', 'DELETE', 'HEAD'],
                    'AllowedOrigins': ['*'],
                    'MaxAgeSeconds': 3000,
                    'ExposeHeaders': ['ETag', 'Content-Disposition']
                }
            ]
        }
        s3_client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)
        
        logger.info(f"Created bucket: {bucket_name}")
        return bucket_name
    except Exception as e:
        logger.error(f"Failed to create bucket {bucket_name}: {str(e)}")
        raise

# Get bucket usage in GB
def get_bucket_usage(bucket_name):
    try:
        total_size = 0
        objects = s3_client.list_objects_v2(Bucket=bucket_name).get('Contents', [])
        for obj in objects:
            total_size += obj['Size']
        return total_size / (1024**3)  # Converting to GB
    except Exception as e:
        logger.error(f"Error getting bucket usage for {bucket_name}: {str(e)}")
        return 0


# Constants
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' # Is valid email
ALLOWED_ACTIONS = {
    'initiate_file_share', 'initiate_decryption', 'create_bucket', 'delete_bucket',
    'set_active_bucket', 'delete_user', 'approve_user', 'disapprove_bucket_request'
}
MAX_DETAILS_LENGTH = 10000  # 10KB for DynamoDB item size limit

# Get active bucket for user
def get_active_bucket(buckets):
    if not buckets:
        return None
    
    for bucket_name in buckets:
        try:
            
            s3_client.head_bucket(Bucket=bucket_name)
            
            
            usage_gb = get_bucket_usage(bucket_name)
            
            if usage_gb < 4.9:  
                return bucket_name
        except Exception as e:
            logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
            continue
    
    return buckets[0] if buckets else None

# Security: Validate file paths
class SecurityError(Exception):
    pass


# Audit logging function
def log_audit_action(user_email, action, details):
    """
    Log an audit action to the LogsTable DynamoDB table.
    """
    try:
        
        if not user_email or not action or not details:
            logger.error(f"Missing required parameters: user_email={user_email}, action={action}, details={details}")
            return False
        
        if len(details) > 4000:  # Reduced from 10000 to be safe
            details = details[:4000] + "... [truncated]"
        
        # Create audit log entry
        audit_logs_table.put_item(
            Item={
                'log_id': str(uuid.uuid4()),
                'user_email': user_email,
                'action': action,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'details': details
            }
        )
        logger.info(f"Audit log recorded: {user_email} - {action}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to log audit action: {str(e)}")
        return False
    

# Routes (unchanged for brevity, same as previous optimized version)
@app.route('/')
def home():
    return render_template('landing.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        master_password = request.form.get('master_password', '')

        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'All fields are required.'})

        if role == 'admin' and master_password != 'your-master-password-for-admin-only':
            return jsonify({'success': False, 'message': 'Incorrect master password for admin.'})

        if not is_strong_password(password):
            return jsonify({'success': False, 'message': 'Password not strong enough.'})

        if users_table.get_item(Key={'email': email}).get('Item'):
            return jsonify({'success': False, 'message': 'Email already registered.'})

        password_hash = pbkdf2_sha256.hash(password)
        approved = role == 'admin'

        users_table.put_item(Item={
            'email': email,
            'username': username,
            'password': password_hash,
            'role': role,
            'approved': approved,
            'buckets': [],
            'active_bucket': None,
            'shares': []
        })
        message = 'Registration successful! ' + ('Login now.' if role == 'admin' else 'Approval by admin is pending.')
        return jsonify({
            'success': True,
            'message': message,
            'category': 'success',
            'redirect_url': url_for('login')
        })
    
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()                    

    admin_user = users_table.scan(
        FilterExpression=Attr('role').eq('admin')
    ).get('Items', [])[0] if users_table.scan(
        FilterExpression=Attr('role').eq('admin')
    ).get('Items', []) else None
    admin_name = admin_user['username'] if admin_user else 'Admin'
    admin_email = admin_user['email'] if admin_user else 'admin@example.com'

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required.'})

        user = users_table.get_item(Key={'email': email}).get('Item')
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email/password.'})

        if user['role'] != 'admin' and not user.get('approved', False):
            return jsonify({'success': False, 'message': 'Your registration is pending admin approval.'})

        stored_pw = user['password'][1:] if user['password'].startswith('@') else user['password']
        if not pbkdf2_sha256.verify(password, stored_pw):
            return jsonify({'success': False, 'message': 'Invalid email/password.'})

        otp = generate_otp()
        session['mfa_otp'] = otp
        session['mfa_otp_time'] = time.time()
        session['user'] = {
            'email': user['email'],
            'username': user['username'],
            'role': user['role'],
            'approved': user.get('approved', False)
        }
        session.modified = True

        try:
            send_mfa_email(email, otp)
            return jsonify({
                'success': True,
                'message': 'Login successful. OTP sent for MFA.',
                'redirect_url': url_for('verify_mfa')
            })
        except Exception as e:
            session.clear()
            return jsonify({'success': False, 'message': f'Failed to send MFA email: {str(e)}'})

    return render_template('login.html', admin_name=admin_name, admin_email=admin_email, admin_user=admin_user)


# Verify MFA route
@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'mfa_otp' not in session or 'mfa_otp_time' not in session or 'user' not in session:
        session.clear()
        return jsonify({
            'success': False,
            'message': 'Session expired. Please login again.',
            
            'redirect_url': url_for('login')
        })

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            return jsonify({
                'success': False,
                'message': 'Please enter the OTP.'
                
            })

        if time.time() - session['mfa_otp_time'] > OTP_EXPIRATION_SECONDS:
            session.clear()
            return jsonify({
                'success': False,
                'message': 'OTP expired. Please login again.',
                
                'redirect_url': url_for('login')
            })

        if otp != session['mfa_otp']:
            return jsonify({
                'success': False,
                'message': 'Incorrect OTP.'
                
            })

        user = session['user']
        session.pop('mfa_otp', None)
        session.pop('mfa_otp_time', None)
        session.permanent = True
        session.modified = True

        return jsonify({
            'success': True,
            'message': 'Login successful!',
            
            'redirect_url': url_for('admin_dashboard' if user['role'] == 'admin' else 'dashboard')
        })

    return render_template('verify_mfa.html', file_share=False, decrypt=False, login=True)

# Helper function to validate email
def is_valid_email(email):
    return bool(re.match(EMAIL_REGEX, email))

# Helper function to process uploaded files 
def process_uploaded_files(files, max_files=5, max_size=MAX_FILE_SIZE):
    if len(files) > max_files:
        raise ValueError(f"Maximum {max_files} files allowed.")
    temp_paths = []
    for f in files:
        if not f.filename or f.filename.strip() == '':
            raise ValueError("One or more files have invalid names.")
        file_data = f.read()
        file_size = len(file_data)
        if file_size > max_size:
            raise ValueError(f"File {f.filename} exceeds {max_size/(1024*1024)}MB limit.")
        safe_name = secure_filename(f.filename)
        temp_path = os.path.join(tempfile.gettempdir(), safe_name)
        f.seek(0)
        f.save(temp_path)
        if not os.path.exists(temp_path):
            raise FileNotFoundError(f"Failed to save file: {safe_name}")
        temp_paths.append(temp_path)
    return temp_paths

# Dashboard route for regular users
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    
    if request.method == 'GET':
        session.pop('mfa_otp', None)
        session.pop('mfa_otp_time', None)
        session.pop('login_email', None)
        session.pop('decrypt_otp', None)
        session.pop('decrypt_otp_time', None)
        session.pop('decrypt_data', None)
        session.pop('file_share_otp', None)
        session.pop('file_share_otp_time', None)
        session.pop('file_share_data', None)
        session.modified = True

    
    if 'user_preauth' in session:
        session['user'] = session.pop('user_preauth')
        session.modified = True
    elif 'user' not in session:
        flash('No user session found. Please login again.', 'error')
        return redirect(url_for('login'))

    user = session['user']
    if user.get('role') != 'user':
        flash('Invalid user role. Please login with a user account.', 'error')
        session.clear()
        return redirect(url_for('login'))

    if not user.get('approved', False):
        flash('Your account is not approved yet. Please contact admin.', 'info')
        return redirect(url_for('login'))

    user_data = users_table.get_item(Key={'email': user['email']}).get('Item', {})
    buckets = user_data.get('buckets', [])
    active_bucket = user_data.get('active_bucket')
    
    if active_bucket:
        try:
            
            s3_client.head_bucket(Bucket=active_bucket)
            
            usage_gb = get_bucket_usage(active_bucket)
            if usage_gb >= 4.9: 
                active_bucket = get_active_bucket(buckets)
                if active_bucket:
                    users_table.update_item(
                        Key={'email': user['email']},
                        UpdateExpression='SET active_bucket = :ab',
                        ExpressionAttributeValues={':ab': active_bucket}
                    )
        except Exception as e:
            logger.error(f"Active bucket {active_bucket} error: {str(e)}")
            active_bucket = get_active_bucket(buckets)
            if active_bucket:
                users_table.update_item(
                    Key={'email': user['email']},
                    UpdateExpression='SET active_bucket = :ab',
                    ExpressionAttributeValues={':ab': active_bucket}
                )
    
    if not active_bucket and buckets:
        active_bucket = get_active_bucket(buckets)
        if active_bucket:
            users_table.update_item(
                Key={'email': user['email']},
                UpdateExpression='SET active_bucket = :ab',
                ExpressionAttributeValues={':ab': active_bucket}
            )

    admin_user = users_table.scan(FilterExpression=Attr('role').eq('admin')).get('Items', [])
    admin_name = admin_user[0]['username'] if admin_user else 'Admin'
    admin_email = admin_user[0]['email'] if admin_user else 'admin@example.com'

    if request.method == 'POST':
        # Handle file sharing
        if 'files' in request.files and request.form.get('recipient_email'):
            files = request.files.getlist('files')
            password = request.form.get('password')
            recipient_email = request.form.get('recipient_email')

            if not files:
                flash('No files selected.', 'error')
                return redirect(url_for('dashboard'))
            if len(files) > 5:
                flash('Maximum 5 files allowed.', 'error')
                return redirect(url_for('dashboard'))
            if not password:
                flash('Encryption password is required.', 'error')
                return redirect(url_for('dashboard'))
            if not password.startswith('@'):
                flash('Encryption password must start with "@".', 'error')
                return redirect(url_for('dashboard'))
            if not recipient_email:
                flash('Recipient email is required.', 'error')
                return redirect(url_for('dashboard'))

            user_data = users_table.get_item(Key={'email': user['email']}).get('Item', {})
            buckets = user_data.get('buckets', [])
            active_bucket = user_data.get('active_bucket')
            
            if not active_bucket:
                active_bucket = get_active_bucket(buckets)
                if active_bucket:
                    users_table.update_item(
                        Key={'email': user['email']},
                        UpdateExpression='SET active_bucket = :ab',
                        ExpressionAttributeValues={':ab': active_bucket}
                    )
            
            if not active_bucket:
                flash('No active bucket available. Please request a new bucket.', 'error')
                return redirect(url_for('dashboard'))

            # Checking temporary directory permissions
            temp_dir = tempfile.gettempdir()
            if not os.access(temp_dir, os.W_OK):
                flash('Server error: No write permission for temporary directory.', 'error')
                return redirect(url_for('dashboard'))

            temp_paths = []
            try:
                for f in files:
                    if not f.filename:
                        flash('One or more files have invalid names.', 'error')
                        raise ValueError('Invalid filename')

                    file_data = f.read()
                    file_size = len(file_data)
                    if file_size > MAX_FILE_SIZE:
                        flash(f'File {f.filename} exceeds 100MB limit.', 'error')
                        raise ValueError(f'File {f.filename} too large')

                    safe_name = secure_filename(f.filename)
                    temp_path = os.path.join(temp_dir, safe_name)
                    f.seek(0)
                    f.save(temp_path)
                    if not os.path.exists(temp_path):
                        raise FileNotFoundError(f'Failed to save file: {safe_name}')
                    temp_paths.append(temp_path)

                otp = generate_otp()
                session['file_share_otp'] = otp
                session['file_share_otp_time'] = time.time()
                session['file_share_data'] = {
                    'files': temp_paths,
                    'password': password,
                    'recipient_email': recipient_email,
                    'active_bucket': active_bucket
                }
                session.modified = True

                try:
                    send_mfa_email(user['email'], otp)
                except botocore.exceptions.ClientError as aws_e:
                    flash(f'Failed to send OTP email: {aws_e.response["Error"]["Message"]}', 'error')
                    raise
                except Exception as email_e:
                    flash(f'Failed to send OTP email: {str(email_e)}', 'error')
                    raise

                session.modified = True
                return redirect(url_for('verify_file_mfa', type='file_share'))

            except ValueError as ve:
                flash(f'Error preparing files: {str(ve)}', 'error')
                for p in temp_paths:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

            except FileNotFoundError as fnf_e:
                flash(f'Error saving files: {str(fnf_e)}', 'error')
                for p in temp_paths:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

            except Exception as e:
                flash(f'Error preparing files or sending OTP: {str(e)}', 'error')
                for p in temp_paths:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

        elif 'files' in request.files and request.form.get('password') and not request.form.get('recipient_email'):
            files = request.files.getlist('files')
            if len(files) > 5:
                flash('Maximum 5 files allowed.', 'error')
                return redirect(url_for('dashboard'))
            if not files:
                flash('No files selected for decryption.', 'error')
                return redirect(url_for('dashboard'))

            password = request.form.get('password')
            if not password:
                flash('Decryption password is required.', 'error')
                return redirect(url_for('dashboard'))

            temp_files = []
            try:
                for f in files:
                    if not f.filename:
                        flash('One or more files have invalid names.', 'error')
                        raise ValueError('Invalid filename')

                    file_data = f.read()
                    file_size = len(file_data)
                    if file_size > MAX_FILE_SIZE:
                        flash(f'File {f.filename} exceeds 100MB limit.', 'error')
                        raise ValueError(f'File {f.filename} too large')

                    safe_name = secure_filename(f.filename)
                    temp_path = os.path.join(tempfile.gettempdir(), safe_name)
                    f.seek(0)
                    f.save(temp_path)
                    if not os.path.exists(temp_path):
                        raise FileNotFoundError(f'Failed to save file: {safe_name}')
                    temp_files.append(temp_path)

                otp = generate_otp()
                session['decrypt_otp'] = otp
                session['decrypt_otp_time'] = time.time()
                session['decrypt_data'] = {
                    'files': temp_files,
                    'password': password
                }
                session.modified = True

                try:
                    send_mfa_email(user['email'], otp)
                except botocore.exceptions.ClientError as aws_e:
                    flash(f'Failed to send OTP email for decryption: {aws_e.response["Error"]["Message"]}', 'error')
                    raise
                except Exception as email_e:
                    flash(f'Failed to send OTP email for decryption: {str(email_e)}', 'error')
                    raise

                session.modified = True
                return redirect(url_for('verify_decrypt_mfa', type='decrypt'))

            except ValueError as ve:
                flash(f'Error preparing files for decryption: {str(ve)}', 'error')
                for p in temp_files:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

            except FileNotFoundError as fnf_e:
                flash(f'Error saving files for decryption: {str(fnf_e)}', 'error')
                for p in temp_files:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

            except Exception as e:
                flash(f'Error preparing files or sending OTP for decryption: {str(e)}', 'error')
                for p in temp_files:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('dashboard'))

        else:
            flash('Invalid form submission. Ensure files and recipient email are provided for sharing, or files and password for decryption.', 'error')
            return redirect(url_for('dashboard'))

    shares_resp = shares_table.query(
        IndexName='sender-email-index',
        KeyConditionExpression=Key('sender_email').eq(user['email']),
        ScanIndexForward=False,
        Limit=10
    )
    last_shares = shares_resp.get('Items', [])

    s3 = boto3.resource('s3')
    used_storage_bytes = 0
    user_data = users_table.get_item(Key={'email': user['email']}).get('Item', {})
    buckets = user_data.get('buckets', [])
    active_bucket = user_data.get('active_bucket')
    
    for bucket_name in buckets:
        try:
            bucket = s3.Bucket(bucket_name)
            for obj in bucket.objects.all():
                used_storage_bytes += obj.size
        except Exception as e:
            flash(f"Error accessing bucket {bucket_name}: {str(e)}", "error")

    used_storage_mb = round(used_storage_bytes / (1024 * 1024), 2)
    total_storage_mb = 5 * 1024
    remaining_storage = total_storage_mb - used_storage_mb
    usage_percent = round((used_storage_mb / total_storage_mb) * 100, 2)
    
    active_bucket = get_active_bucket(buckets)

    return render_template(
        'dashboard.html',
        username=user['username'],
        role='user',
        past_shares=last_shares,
        admin_name=admin_name,
        admin_email=admin_email,
        remaining_storage=remaining_storage,
        used_storage=used_storage_mb,
        total_storage=total_storage_mb,
        usage_percent=usage_percent,
        active_bucket=active_bucket,
        buckets=buckets
    )


# Verify File Share MFA Route
@app.route('/verify_file_mfa', methods=['GET', 'POST'])
def verify_file_mfa():
    # Check if user is authenticated
    if 'user' not in session or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        return jsonify({
            'success': False,
            'message': 'Session expired. Please login again.',
            'redirect_url': url_for('login')
        })

    user = session['user']
    user_role = user.get('role')
    
    # Determining redirect destination based on role
    redirect_target = 'admin_dashboard' if user_role == 'admin' else 'dashboard'

    if 'file_share_otp' not in session or 'file_share_data' not in session:
        return jsonify({
            'success': False, 
            'message': 'No file sharing session found.',
            'redirect_url': url_for(redirect_target)
        })

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            return jsonify({
                'success': False,
                'message': 'OTP is required.'
            })

        if otp != session['file_share_otp']:
            return jsonify({
                'success': False,
                'message': 'Invalid OTP.'
            })                            

        # Check OTP expiration (5 mins)
        otp_time = session.get('file_share_otp_time', 0)
        if time.time() - otp_time > 300:
            session.pop('file_share_otp', None)
            session.pop('file_share_otp_time', None)
            session.pop('file_share_data', None)
            return jsonify({
                'success': False,
                'message': 'OTP has expired.',
                'redirect_url': url_for(redirect_target)
            })

        file_share_data = session['file_share_data']
        files = file_share_data['files']
        password = file_share_data['password']
        recipient_email = file_share_data['recipient_email']
        active_bucket = file_share_data['active_bucket']
        
        bucket_owner = file_share_data.get('bucket_owner', user['email'])

        try:
            # Verify bucket accessibility
            try:
                s3_client.head_bucket(Bucket=active_bucket)
                logger.info(f"Bucket {active_bucket} is accessible")
            except Exception as bucket_error:
                logger.error(f"Bucket {active_bucket} is not accessible: {str(bucket_error)}")
                return jsonify({
                    'success': False,
                    'message': f'Storage bucket error: {str(bucket_error)}',
                    'redirect_url': url_for(redirect_target)
                })

            # Measure encryption time
            start_time = time.time()
            
            encrypted_filenames = []
            for file_path in files:
                try:
                    # Run AES encryption
                    encrypted_path, _ = run_aes_command("encrypt", password, file_path, tempfile.gettempdir())                      
                    encrypted_filename = os.path.basename(encrypted_path)
                    
                    # Upload to S3 
                    try:
                        s3_client.upload_file(
                            encrypted_path,
                            active_bucket,
                            encrypted_filename,
                            ExtraArgs={
                                'ContentType': 'application/octet-stream',
                                'ContentDisposition': f'attachment; filename="{encrypted_filename}"'
                            }
                        )
                        logger.info(f"Successfully uploaded {encrypted_filename} to S3 bucket {active_bucket}")
                        
                        # Verify upload exists in S3
                        try:
                            s3_client.head_object(Bucket=active_bucket, Key=encrypted_filename)
                            logger.info(f"Verified {encrypted_filename} exists in S3")
                            encrypted_filenames.append(encrypted_filename)
                            
                        except Exception as verify_error:
                            logger.error(f"Upload verification FAILED for {encrypted_filename}: {str(verify_error)}")
                            # Re-upload using put_object 
                            try:
                                with open(encrypted_path, 'rb') as f:
                                    file_data = f.read()
                                    s3_client.put_object(
                                        Bucket=active_bucket,
                                        Key=encrypted_filename,
                                        Body=file_data,
                                        ContentType='application/octet-stream',
                                        ContentDisposition=f'attachment; filename="{encrypted_filename}"'
                                    )
                                logger.info(f"Successfully re-uploaded {encrypted_filename} using put_object")
                                
                                s3_client.head_object(Bucket=active_bucket, Key=encrypted_filename)
                                logger.info(f"Verified {encrypted_filename} exists after re-upload")
                                encrypted_filenames.append(encrypted_filename)
                                
                            except Exception as reupload_error:
                                logger.error(f"Re-upload also failed: {str(reupload_error)}")
                                continue
                            
                    except Exception as upload_error:
                        logger.error(f"Failed to upload {encrypted_filename} to S3: {str(upload_error)}")
                        continue
                    
                except Exception as file_error:
                    logger.error(f"Failed to process file {file_path}: {str(file_error)}")
                    continue
            
            encryption_time = time.time() - start_time
            
            if not encrypted_filenames:
                return jsonify({
                    'success': False,
                    'message': 'No files were successfully uploaded to S3',
                    'redirect_url': url_for(redirect_target)
                })
            
            # Create share record
            share_id = str(uuid.uuid4())
            shares_table.put_item(
                Item={
                    'share_id': share_id,
                    'sender_email': bucket_owner,
                    'recipient_email': recipient_email,
                    'files': encrypted_filenames,
                    'timestamp': datetime.datetime.utcnow().isoformat()
                }
            )

            # Send email with download links
            try:
                send_file_sharing_email(
                    sender_email=bucket_owner,
                    recipient_email=recipient_email,
                    cc_email=None,
                    files=encrypted_filenames,
                    bucket=active_bucket,
                    password=password
                )
            except Exception as email_error:
                logger.error(f"Failed to send email: {str(email_error)}")

            # Log the action
            log_audit_action(
                user['email'],
                'file_share',
                f"Shared {len(encrypted_filenames)} files with {recipient_email} in {encryption_time:.2f} seconds from bucket {active_bucket}"
            )

            # Clean up temporary files
            for p in files:
                if os.path.exists(p):
                    os.remove(p)
            for file_path in files:
                encrypted_path = os.path.join(tempfile.gettempdir(), os.path.basename(file_path) + "_encrypted")
                if os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
            
            # Clear session data
            session.pop('file_share_otp', None)
            session.pop('file_share_otp_time', None)
            session.pop('file_share_data', None)

            return jsonify({
                'success': True,
                'message': f'Files shared successfully in {encryption_time:.2f} seconds! Recipient will receive an email.',
                'redirect_url': url_for(redirect_target)
            })

        except Exception as e:
            logger.error(f"Error sharing files: {str(e)}")
            
            # Clean up temporary files on error 
            for p in files:
                if os.path.exists(p):
                    os.remove(p)
            return jsonify({
                'success': False,
                'message': f'Error sharing files: {str(e)}',
                'redirect_url': url_for(redirect_target)
            })
    action_type = request.args.get('type', 'file_share')
    return render_template('verify_mfa.html', action='file sharing', type=action_type)

# AES command execution 
def run_aes_command(mode, password, input_path, output_dir):                              
    """
    Run AES encryption/decryption command with better error handling
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    input_filename = os.path.basename(input_path)
    stem, ext = os.path.splitext(input_filename)
    
    suffix = "_decrypted" if mode == "decrypt" else "_encrypted"
    output_filename = f"{stem}{suffix}{ext}"
    output_path = os.path.join(output_dir, output_filename)
    
    try:
        # Run the AES command
        cmd = [AES_EXE_PATH, mode, password, output_dir, input_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # 5 minute timeout
        )
        
        # Check if output file was created
        if not os.path.exists(output_path):
            
            possible_patterns = [
                output_path,
                os.path.join(output_dir, f"{stem}{suffix}"),
                os.path.join(output_dir, f"{input_filename}{suffix}"),
                os.path.join(output_dir, f"{input_filename}.encrypted"),
                os.path.join(output_dir, f"{input_filename}.decrypted")
            ]
            
            for pattern in possible_patterns:
                if os.path.exists(pattern):
                    output_path = pattern
                    break
            else:
                raise FileNotFoundError(f"Output file not created: {output_path}")
        
        return output_path, result.stdout
        
    except subprocess.CalledProcessError as e:
        error_msg = f"{mode.capitalize()} failed: {e.stderr}"
        logger.error(f"AES command error: {error_msg}")
        raise Exception(error_msg)
        
    except subprocess.TimeoutExpired:
        error_msg = f"{mode.capitalize()} timed out after 5 minutes"
        logger.error(error_msg)
        raise Exception(error_msg)
        
    except Exception as e:
        error_msg = f"{mode.capitalize()} error: {str(e)}"
        logger.error(f"AES unexpected error: {error_msg}")                      
        raise Exception(error_msg)

# Send file sharing email with download links
def send_file_sharing_email(sender_email, recipient_email, cc_email, files, bucket, password=None):
    body_text = f"You have received {len(files)} file(s) from {sender_email}.\n\n"
    body_html = f"<p>You have received {len(files)} file(s) from {sender_email}.</p><ul>"
    
    download_links = []
    for enc_filename in files:
        try:
            # Generate presigned URL - FIXED PARAMETERS
            presigned_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': bucket,
                    'Key': enc_filename
                },
                ExpiresIn=1800  # 30 minutes
            )
            
            # Use the full URL without shortening
            download_links.append(f"{enc_filename}: {presigned_url}")
            body_html += f'<li>{enc_filename}: <a href="{presigned_url}">Download File</a> (Full URL: {presigned_url})</li>'
            logger.info(f"Generated presigned URL for {enc_filename}")
            
        except Exception as e:
            logger.error(f"Error generating download link for {enc_filename}: {str(e)}")
            download_links.append(f"Error for {enc_filename}: {str(e)}")
            body_html += f'<li>{enc_filename}: Failed to generate download link ({str(e)})</li>'

    body_text += "Files & Download Links:\n" + "\n".join(download_links)
    body_html += "</ul>"
    
    if password:
        body_text += f"\n\nDecryption password: {password}\nNote: Keep this password secure and do not share it publicly."
        body_html += f"<p>Decryption password: {password}<br><strong>Note:</strong> Keep this password secure and do not share it publicly.</p>"

    try:
        ses_client.send_email(
            Source=SES_CONSTANT_SENDER,
            Destination={
                'ToAddresses': [recipient_email],
                'CcAddresses': [cc_email] if cc_email else []
            },
            Message={
                'Subject': {'Data': 'Files Shared With You'},
                'Body': {
                    'Text': {'Data': body_text},
                    'Html': {'Data': body_html}
                }
            }
        )
        logger.info(f"Email sent to {recipient_email} with CC to {cc_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise


# Verify Decrypt MFA Route
@app.route('/verify_decrypt_mfa', methods=['GET', 'POST'])
def verify_decrypt_mfa():
    # Check if user is authenticated 
    if 'user' not in session or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        return jsonify({
            'success': False,
            'message': 'Invalid or tampered session. Please login again.',
            'redirect_url': url_for('login')
        })

    user = session['user']
    user_role = user.get('role')
    
    # Determine redirect destination based on role
    redirect_target = 'admin_dashboard' if user_role == 'admin' else 'dashboard'

    if 'decrypt_otp' not in session or 'decrypt_data' not in session:
        return jsonify({
            'success': False,
            'message': 'No decryption session found.',
            'redirect_url': url_for(redirect_target)
        })

    if request.method == 'POST':
        otp = request.form.get('otp')
        if not otp:
            return jsonify({
                'success': False,
                'message': 'OTP is required.'
            })

        if otp != session['decrypt_otp']:
            return jsonify({
                'success': False,
                'message': 'Invalid OTP.'
            })

        # Check OTP expiration (5 minutes)
        otp_time = session.get('decrypt_otp_time', 0)
        if time.time() - otp_time > 300:
            session.pop('decrypt_otp', None)
            session.pop('decrypt_otp_time', None)
            session.pop('decrypt_data', None)
            return jsonify({
                'success': False,
                'message': 'OTP has expired.',
                'redirect_url': url_for(redirect_target)
            })

        decrypt_data = session['decrypt_data']
        files = decrypt_data['files']
        password = decrypt_data['password']

        try:
            # Create a temporary directory for decrypted files
            temp_dir = tempfile.mkdtemp()
            decrypted_files = []
            
            # Measure encryption/decryption time
            start_time = time.time()
            
            # Decrypt each file
            for file_path in files:
                decrypted_path, _ = run_aes_command("decrypt", password, file_path, temp_dir)
                decrypted_files.append(decrypted_path)
            
            decryption_time = time.time() - start_time
            
            # Create a zip file with all decrypted files
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for decrypted_file in decrypted_files:
                    zip_file.write(decrypted_file, os.path.basename(decrypted_file))
            
            zip_buffer.seek(0)
            
            # Store the zip file in session for download
            session['decrypted_zip'] = zip_buffer.getvalue()
            session['decrypted_filename'] = f"decrypted_files_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}.zip"
            
            # Log the action
            log_audit_action(
                user['email'],
                'file_decrypt',
                f"Decrypted {len(files)} files in {decryption_time:.2f} seconds"
            )
            
            # Clean up temporary files
            for p in files:
                if os.path.exists(p):
                    os.remove(p)
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Clear session data
            session.pop('decrypt_otp', None)
            session.pop('decrypt_otp_time', None)
            session.pop('decrypt_data', None)

            return jsonify({
                'success': True,
                'message': f'Files decrypted successfully in {decryption_time:.2f} seconds. Download starting...',
                'redirect_url': url_for('download_decrypted'),
                'auto_download': True
            })

        except Exception as e:
            logger.error(f"Error decrypting files: {str(e)}")
            # Clean up temporary files on error
            for p in files:
                if os.path.exists(p):
                    os.remove(p)
            return jsonify({
                'success': False,
                'message': f'Error decrypting files: {str(e)}'
            })
    action_type = request.args.get('type', 'decrypt')
    return render_template('verify_mfa.html', action='decryption', type=action_type)

# Route to download decrypted zip file
@app.route('/download_decrypted')
def download_decrypted():
    if 'decrypted_zip' not in session or 'decrypted_filename' not in session:
        flash('No decrypted files found.', 'error')
        return redirect(url_for('dashboard' if session.get('user', {}).get('role') == 'user' else 'admin_dashboard'))
    
    zip_data = session.pop('decrypted_zip')
    filename = session.pop('decrypted_filename')
    
    return send_file(
        BytesIO(zip_data),
        as_attachment=True,
        download_name=filename,
        mimetype='application/zip'
    )

# Admin Dashboard Route
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    # Enhanced session validation
    if 'user' not in session or session['user'].get('role') != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    admin_user = session['user']
    all_users = []
    bucket_requests = []
    total_shares = 0
    used_storage_bytes = 0
    usage_percent = 0
    remaining_storage = TOTAL_STORAGE_MB

    try:
        # Fetch admin's data 
        try:
            admin_data = users_table.get_item(Key={'email': admin_user['email']}).get('Item', {})
            admin_buckets = admin_data.get('buckets', [])
            admin_active_bucket = admin_data.get('active_bucket', None)
        except ClientError as e:
            logger.error(f"DynamoDB error fetching admin data: {str(e)}")
            flash("Error accessing admin data. Please try again.", 'error')
            return redirect(url_for('admin_dashboard'))

        # Fetch users with batch_get_item for efficiency
        try:
            user_emails = [user['email'] for user in users_table.scan(ProjectionExpression='email').get('Items', [])]
            if user_emails:
                batch_keys = {'UsersTable': {'Keys': [{'email': email} for email in user_emails]}}
                response = dynamodb.batch_get_item(RequestItems=batch_keys)
                all_users = response.get('Responses', {}).get('UsersTable', [])
        except ClientError as e:
            logger.error(f"Failed to batch fetch users: {str(e)}")
            flash(f"Error retrieving users: {str(e)}", 'error')

        # Fetch bucket requests
        try:
            bucket_requests = bucket_requests_table.scan(
                FilterExpression=Attr('status').eq('pending')
            ).get('Items', [])
        except ClientError as e:
            logger.error(f"Failed to scan : RequestsTable {str(e)}")
            flash(f"Error retrieving bucket requests: {str(e)}", 'error')

        # Cache bucket usage to avoid repeated calls
        bucket_usage_cache = {}
        for u in all_users:
            try:
                shares_resp = shares_table.query(
                    IndexName='sender-email-index',
                    KeyConditionExpression=Key('sender_email').eq(u['email'])
                )
                u['shares'] = shares_resp.get('Items', [])
            except ClientError as e:
                logger.error(f"Failed to query shares for user {u['email']}: {str(e)}")
                u['shares'] = []
                flash(f"Error retrieving shares for {u['email']}: {str(e)}", 'error')

            u['buckets'] = u.get('buckets', [])
            u['active_bucket'] = u.get('active_bucket', None)
            u['storage_usage'] = {}
            u['total_usage_gb'] = 0
            for bucket_name in u.get('buckets', []):
                try:
                    if bucket_name not in bucket_usage_cache:
                        bucket_usage_cache[bucket_name] = get_bucket_usage(bucket_name)
                    usage_gb = bucket_usage_cache[bucket_name]
                    u['storage_usage'][bucket_name] = round(usage_gb, 2)
                    u['total_usage_gb'] += usage_gb
                    used_storage_bytes += usage_gb * (1024 ** 3)
                except ClientError as e:
                    logger.error(f"Error getting usage for bucket {bucket_name}: {str(e)}")
                    u['storage_usage'][bucket_name] = 0

        # Admin storage usage
        admin_storage_usage = {}
        admin_total_usage_gb = 0
        for bucket_name in admin_buckets:
            try:
                if bucket_name not in bucket_usage_cache:
                    bucket_usage_cache[bucket_name] = get_bucket_usage(bucket_name)
                usage_gb = bucket_usage_cache[bucket_name]
                admin_storage_usage[bucket_name] = round(usage_gb, 2)
                admin_total_usage_gb += usage_gb
                used_storage_bytes += usage_gb * (1024 ** 3)
            except ClientError as e:
                logger.error(f"Error getting usage for admin bucket {bucket_name}: {str(e)}")
                admin_storage_usage[bucket_name] = 0

        # Fetch total shares
        try:
            total_shares = len(shares_table.scan().get('Items', []))
        except ClientError as e:
            logger.error(f"Failed to scan SharesTable for total shares: {str(e)}")
            flash(f"Error retrieving total shares: {str(e)}", 'error')

        # Calculate storage metrics
        used_storage_mb = round(used_storage_bytes / (1024 * 1024), 2)
        usage_percent = round((used_storage_mb / TOTAL_STORAGE_MB) * 100, 2)
        remaining_storage = max(0, TOTAL_STORAGE_MB - used_storage_mb)

    except Exception as e:
        logger.error(f"Error in admin_dashboard: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", 'error')

    if request.method == 'POST':
        files = request.files.getlist('files')
        password = request.form.get('password')
        recipient_email = request.form.get('recipient_email', '')

        if files and password and recipient_email:
            if not password.startswith('@'):
                flash('Encryption password must start with "@".', 'error')
                return redirect(url_for('admin_dashboard'))
            if not is_valid_email(recipient_email):
                flash('Invalid recipient email format.', 'error')
                return redirect(url_for('admin_dashboard'))

            # Use admin's own bucket
            active_bucket = admin_active_bucket
            if not active_bucket:
                active_bucket = get_active_bucket(admin_buckets)
                if active_bucket:
                    try:
                        users_table.update_item(
                            Key={'email': admin_user['email']},
                            UpdateExpression='SET active_bucket = :ab',
                            ExpressionAttributeValues={':ab': active_bucket}
                        )
                        if not log_audit_action(
                            admin_user['email'],
                            'set_active_bucket',
                            f"Set active bucket to {active_bucket}"
                        ):
                            flash("Failed to log bucket selection.", 'error')
                    except ClientError as e:
                        logger.error(f"Error updating active bucket: {str(e)}")
                        flash("Error setting active bucket.", 'error')
                        return redirect(url_for('admin_dashboard'))
                else:
                    flash('No active bucket available. Please add a bucket first.', 'error')
                    return redirect(url_for('admin_dashboard'))

            temp_paths = []
            try:
                temp_paths = process_uploaded_files(files)
                otp = generate_otp()
                session['file_share_otp'] = otp
                session['file_share_otp_time'] = time.time()
                session['file_share_data'] = {
                    'files': temp_paths,
                    'password': password,
                    'recipient_email': recipient_email,
                    'active_bucket': active_bucket,
                    'bucket_owner': admin_user['email']
                }
                session.modified = True

                try:
                    send_mfa_email(admin_user['email'], otp)
                    if not log_audit_action(
                        admin_user['email'],
                        'initiate_file_share',
                        f"Prepared to share {len(temp_paths)} files ({', '.join([os.path.basename(p) for p in temp_paths])}) with {recipient_email} using bucket {active_bucket}"
                    ):
                        flash("Failed to log file sharing action.", 'error')
                except Exception as e:
                    flash(f'Failed to send OTP email: {str(e)}', 'error')
                    for p in temp_paths:
                        if os.path.exists(p):
                            os.remove(p)
                    return redirect(url_for('admin_dashboard'))

                session.modified = True
                return redirect(url_for('verify_file_mfa', type='file_share'))

            except (ValueError, FileNotFoundError) as e:
                flash(f'Error preparing files: {str(e)}', 'error')
                for p in temp_paths:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                flash(f'Unexpected error preparing files: {str(e)}', 'error')
                for p in temp_paths:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('admin_dashboard'))

        elif files and password:
            try:
                temp_files = process_uploaded_files(files)
                otp = generate_otp()
                session['decrypt_otp'] = otp
                session['decrypt_otp_time'] = time.time()
                session['decrypt_data'] = {
                    'files': temp_files,
                    'password': password
                }
                session.modified = True

                try:
                    send_mfa_email(admin_user['email'], otp)
                    if not log_audit_action(
                        admin_user['email'],
                        'initiate_decryption',
                        f"Prepared to decrypt {len(temp_files)} files ({', '.join([os.path.basename(p) for p in temp_files])})"
                    ):
                        flash("Failed to log decryption action.", 'error')
                
                    session.modified = True
                    return redirect(url_for('verify_decrypt_mfa', type='decrypt'))
                except Exception as e:
                    flash(f'Failed to send OTP email: {str(e)}', 'error')
                    for p in temp_files:
                        if os.path.exists(p):
                            os.remove(p)
                    return redirect(url_for('admin_dashboard'))

            except (ValueError, FileNotFoundError) as e:
                flash(f'Error preparing files for decryption: {str(e)}', 'error')
                for p in temp_files:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                flash(f'Unexpected error preparing files for decryption: {str(e)}', 'error')
                for p in temp_files:
                    if os.path.exists(p):
                        os.remove(p)
                return redirect(url_for('admin_dashboard'))

        else:
            flash('Invalid form submission. Ensure files and recipient email are provided for sharing, or files and password for decryption.', 'error')
            return redirect(url_for('admin_dashboard'))

    pending_users = [u for u in all_users if not u.get('approved', False)]
    total_users = len(all_users)

    return render_template(
        'admin_dashboard.html',
        username=admin_user['username'],
        role='admin',
        total_users=total_users,
        total_shares=total_shares,
        all_users=all_users,
        pending_users=pending_users,
        bucket_requests=bucket_requests,
        admin_name=admin_user['username'],
        admin_email=admin_user['email'],
        remaining_storage=remaining_storage,
        used_storage=used_storage_mb,
        total_storage=TOTAL_STORAGE_MB,
        usage_percent=usage_percent,
        active_bucket=admin_active_bucket,
        buckets=admin_buckets,
        admin_storage_usage=admin_storage_usage,
        admin_total_usage_gb=admin_total_usage_gb
    )

# View All Users Route with Filtering
@app.route('/view_all_users', methods=['GET'])
def view_all_users():
    if 'user' not in session or session['user'].get('role') != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    try:
        # Filter parameters
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')
        
        # Fetch all users
        all_users = users_table.scan().get('Items', [])
        
        # Apply filters
        filtered_users = all_users
        if role_filter:
            filtered_users = [u for u in filtered_users if u.get('role') == role_filter]
        if status_filter:
            if status_filter == 'approved':
                filtered_users = [u for u in filtered_users if u.get('approved')]
            elif status_filter == 'pending':
                filtered_users = [u for u in filtered_users if not u.get('approved')]
        
        # Calculate storage usage for each user
        for user in filtered_users:
            user['total_usage_gb'] = 0
            user['storage_usage'] = {}
            for bucket_name in user.get('buckets', []):
                try:
                    usage_gb = get_bucket_usage(bucket_name)
                    user['storage_usage'][bucket_name] = round(usage_gb, 2)
                    user['total_usage_gb'] += usage_gb
                except Exception:
                    user['storage_usage'][bucket_name] = 0
        
        # Get unique roles for filter dropdowns
        unique_roles = sorted(set(user.get('role', '') for user in all_users))
        
        return render_template(
            'view_all_users.html',
            users=filtered_users,
            unique_roles=unique_roles,
            current_role_filter=role_filter,
            current_status_filter=status_filter
        )
        
    except Exception as e:
        logger.error(f"Error retrieving users: {str(e)}")
        flash(f"Error retrieving users: {str(e)}", 'error')
        return redirect(url_for('admin_dashboard'))

# Add Bucket Route
@app.route('/add_bucket/<email>', methods=['POST'])
def add_bucket(email):
    if 'user' not in session or session['user']['role'] != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    user = users_table.get_item(Key={'email': email}).get('Item')
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        bucket_name = create_user_bucket(user['username'])
        
        # Get current buckets and update the list
        current_buckets = user.get('buckets', [])
        current_buckets.append(bucket_name)
        
        # Update DynamoDB
        users_table.update_item(
            Key={'email': email},
            UpdateExpression='SET buckets = :b, active_bucket = :ab',
            ExpressionAttributeValues={
                ':b': current_buckets,
                ':ab': bucket_name  # Set the new bucket as active
            }
        )
        
        flash(f'Bucket {bucket_name} added and set as active for {email}.', 'success')
        
    except Exception as e:
        logger.error(f"Error adding bucket: {str(e)}")
        flash(f"Error adding bucket: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Delete User Route
@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'user' not in session or session['user'].get('role') != 'admin' or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        flash('Invalid or tampered session. Please login again.', 'error')
        return redirect(url_for('login'))

    user_email = request.form.get('user_email')
    if not user_email or not is_valid_email(user_email):
        flash('Invalid or missing user email.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        user = users_table.get_item(Key={'email': user_email}).get('Item')
        if not user:
            flash(f"User {user_email} not found.", 'error')
            return redirect(url_for('admin_dashboard'))

        for bucket in user.get('buckets', []):
            try:
                bucket_objects = s3_client.list_objects_v2(Bucket=bucket)
                if 'Contents' in bucket_objects:
                    for obj in bucket_objects['Contents']:
                        s3_client.delete_object(Bucket=bucket, Key=obj['Key'])
                s3_client.delete_bucket(Bucket=bucket)
                if not log_audit_action(
                    session['user']['email'],
                    'delete_bucket',
                    f"Deleted bucket {bucket} for user {user_email}"
                ):
                    flash(f"Failed to log bucket deletion for {bucket}.", 'error')                                  
            except ClientError as e:
                logger.error(f"Error deleting bucket {bucket}: {str(e)}")
                flash(f"Error deleting bucket {bucket}: {str(e)}", 'error')

        users_table.delete_item(Key={'email': user_email})
        shares_resp = shares_table.query(
            IndexName='sender-email-index',
            KeyConditionExpression=Key('sender_email').eq(user_email)
        )
        for share in shares_resp.get('Items', []):
            shares_table.delete_item(Key={'share_id': share['share_id']})

        if not log_audit_action(
            session['user']['email'],
            'delete_user',
            f"Deleted user {user_email} with username {user.get('username', 'N/A')} and buckets {user.get('buckets', [])}"
        ):
            flash("Failed to log user deletion.", 'error')
        flash(f"User {user_email} deleted successfully.", 'success')
    except ClientError as e:
        logger.error(f"Error deleting user {user_email}: {str(e)}")
        flash(f"Error deleting user: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Clear Audit Logs Route
@app.route('/clear_audit_logs', methods=['POST'])
def clear_audit_logs():
    if 'user' not in session or session['user'].get('role') != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    try:
        # Scan and delete all audit log items
        response = audit_logs_table.scan()
        for item in response.get('Items', []):
            audit_logs_table.delete_item(Key={'log_id': item['log_id']})
        
        while 'LastEvaluatedKey' in response:
            response = audit_logs_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            for item in response.get('Items', []):
                audit_logs_table.delete_item(Key={'log_id': item['log_id']})
        
        # Log the clearing action
        if not log_audit_action(
            session['user']['email'],
            'clear_audit_logs',
            "Cleared all audit logs"
        ):
            flash("Failed to log audit logs clearance.", 'error')
            
        flash('All audit logs cleared successfully.', 'success')
        
    except Exception as e:
        logger.error(f"Error clearing audit logs: {str(e)}")
        flash(f"Error clearing audit logs: {str(e)}", 'error')

    return redirect(url_for('audit_logs'))

# View Audit Logs Route with Filtering
@app.route('/audit_logs', methods=['GET'])
def audit_logs():
    if 'user' not in session or session['user'].get('role') != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    try:
        # Filter parameters
        user_filter = request.args.get('user_email', '')
        action_filter = request.args.get('action', '')
        date_filter = request.args.get('date', '')
        
        # Build filter expression
        filter_expr = None
        if user_filter:
            filter_expr = Attr('user_email').eq(user_filter)
        if action_filter:
            if filter_expr:
                filter_expr = filter_expr & Attr('action').eq(action_filter)
            else:
                filter_expr = Attr('action').eq(action_filter)
        if date_filter:
            if filter_expr:
                filter_expr = filter_expr & Attr('timestamp').begins_with(date_filter)
            else:
                filter_expr = Attr('timestamp').begins_with(date_filter)
        
        # Scan with filter if provided, otherwise get all logs
        if filter_expr:
            audit_logs = audit_logs_table.scan(
                FilterExpression=filter_expr,
                Limit=200
            ).get('Items', [])
        else:
            audit_logs = audit_logs_table.scan(Limit=200).get('Items', [])
        
        # Sort by timestamp
        audit_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Get unique users and actions for filter dropdowns
        all_logs = audit_logs_table.scan().get('Items', [])
        unique_users = sorted(set(log['user_email'] for log in all_logs))
        unique_actions = sorted(set(log['action'] for log in all_logs))
        
        return render_template(
            'audit_logs.html',
            audit_logs=audit_logs,
            unique_users=unique_users,
            unique_actions=unique_actions,
            current_user_filter=user_filter,
            current_action_filter=action_filter,
            current_date_filter=date_filter
        )
        
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {str(e)}")
        flash(f"Error retrieving audit logs: {str(e)}", 'error')
        return redirect(url_for('admin_dashboard'))

# Disapprove Bucket Request
@app.route('/disapprove_bucket_request', methods=['POST'])                                              
def disapprove_bucket_request():
    if 'user' not in session or session['user'].get('role') != 'admin' or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        flash('Invalid or tampered session. Please login again.', 'error')
        return redirect(url_for('login'))

    request_id = request.form.get('request_id')
    if not request_id:
        flash('No request ID provided.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        bucket_requests_table.update_item(
            Key={'request_id': request_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'disapproved'}
        )
        if not log_audit_action(
            session['user']['email'],
            'disapprove_bucket_request',
            f"Disapproved bucket request {request_id}"
        ):
            flash("Failed to log bucket request disapproval.", 'error')
        flash('Bucket request disapproved successfully.', 'success')
    except ClientError as e:
        logger.error(f"Error disapproving bucket request {request_id}: {str(e)}")
        flash(f"Error disapproving bucket request: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Delete Bucket Route
@app.route('/delete_bucket/<email>', methods=['POST'])
def delete_bucket(email):
    if 'user' not in session or session['user'].get('role') != 'admin' or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        flash('Invalid or tampered session. Please login again.', 'error')
        return redirect(url_for('login'))

    if not is_valid_email(email):
        flash('Invalid user email.', 'error')
        return redirect(url_for('admin_dashboard'))

    bucket_to_delete = request.form.get('bucket_to_delete')
    if not bucket_to_delete:
        flash('No bucket selected for deletion.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        user = users_table.get_item(Key={'email': email}).get('Item')
        if not user or bucket_to_delete not in user.get('buckets', []):
            flash(f"Bucket {bucket_to_delete} not found for user {email}.", 'error')
            return redirect(url_for('admin_dashboard'))

        # Delete bucket contents and bucket
        bucket_objects = s3_client.list_objects_v2(Bucket=bucket_to_delete)
        if 'Contents' in bucket_objects:
            for obj in bucket_objects['Contents']:
                s3_client.delete_object(Bucket=bucket_to_delete, Key=obj['Key'])
        s3_client.delete_bucket(Bucket=bucket_to_delete)

        # Update user buckets
        updated_buckets = [b for b in user.get('buckets', []) if b != bucket_to_delete]
        active_bucket = user.get('active_bucket')
        update_expression = 'SET #buckets = :buckets'
        expression_values = {':buckets': updated_buckets}
        if active_bucket == bucket_to_delete:
            new_active_bucket = updated_buckets[0] if updated_buckets else None
            update_expression += ', active_bucket = :ab'
            expression_values[':ab'] = new_active_bucket
        users_table.update_item(
            Key={'email': email},
            UpdateExpression=update_expression,
            ExpressionAttributeNames={'#buckets': 'buckets'},
            ExpressionAttributeValues=expression_values
        )

        if not log_audit_action(
            session['user']['email'],
            'delete_bucket',
            f"Deleted bucket {bucket_to_delete} for user {email}"
        ):
            flash("Failed to log bucket deletion.", 'error')
        flash(f"Bucket {bucket_to_delete} deleted successfully.", 'success')
    except ClientError as e:
        logger.error(f"Error deleting bucket {bucket_to_delete} for {email}: {str(e)}")
        flash(f"Error deleting bucket: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Request New Bucket Route
@app.route('/request_new_bucket', methods=['GET', 'POST'])
def request_new_bucket():
    if 'user' not in session:
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    user = session['user']
    if not all(key in user for key in ['email', 'username', 'role']):
        session.clear()
        flash('Invalid user data. Please login again.', 'error')
        return redirect(url_for('login'))

    if user.get('role') == 'admin':
        flash('Admins cannot request buckets.', 'error')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        try:
            buckets = user.get('buckets', [])
            if get_active_bucket(buckets):
                flash('You still have an active bucket with available space.', 'error')
                return redirect(url_for('dashboard'))

            request_id = str(uuid.uuid4())
            bucket_requests_table.put_item(Item={
                'request_id': request_id,
                'user_email': user['email'],
                'username': user['username'],
                'status': 'pending',
                'timestamp': datetime.datetime.now().isoformat()
            })
            flash('Bucket request submitted. Waiting for admin approval.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(f"Error submitting bucket request: {str(e)}", 'error')
            return redirect(url_for('dashboard'))

    return render_template('request_bucket.html')

# Approve Bucket Request Route
@app.route('/approve_bucket_request', methods=['POST'])
def approve_bucket_request():
    if 'user' not in session or session['user'].get('role') != 'admin' or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        flash('Invalid or tampered session. Please login again.', 'error')
        return redirect(url_for('login'))

    request_id = request.form.get('request_id')
    user_email = request.form.get('user_email')
    if not request_id or not user_email or not is_valid_email(user_email):
        flash('Invalid request ID or user email.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        request_data = bucket_requests_table.get_item(Key={'request_id': request_id}).get('Item')
        if not request_data or request_data['user_email'] != user_email:
            flash(f"Bucket request {request_id} not found or invalid.", 'error')
            return redirect(url_for('admin_dashboard'))

        bucket_name = create_user_bucket(request_data['username'])
        users_table.update_item(
            Key={'email': user_email},
            UpdateExpression='SET #buckets = list_append(if_not_exists(#buckets, :empty_list), :b), active_bucket = :ab',
            ExpressionAttributeNames={'#buckets': 'buckets'},
            ExpressionAttributeValues={
                ':b': [bucket_name],
                ':ab': bucket_name,
                ':empty_list': []
            }
        )
        bucket_requests_table.update_item(
            Key={'request_id': request_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'approved'}
        )

        if not log_audit_action(
            session['user']['email'],
            'approve_bucket_request',
            f"Approved bucket request {request_id} for user {user_email}, created bucket {bucket_name}"
        ):
            flash("Failed to log bucket request approval.", 'error')
        flash(f"Bucket request {request_id} approved, bucket {bucket_name} created.", 'success')
    except ClientError as e:
        logger.error(f"Error approving bucket request {request_id}: {str(e)}")
        flash(f"Error approving bucket request: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Add Admin Bucket Route
@app.route('/add_admin_bucket', methods=['POST'])
def add_admin_bucket():
    if 'user' not in session or session['user'].get('role') != 'admin':
        session.clear()
        flash('Invalid session. Please login again.', 'error')
        return redirect(url_for('login'))

    admin_user = session['user']
    try:
        # Get current admin data from DynamoDB
        admin_data = users_table.get_item(Key={'email': admin_user['email']}).get('Item', {})
        current_buckets = admin_data.get('buckets', [])
        
        if current_buckets:
            flash('You already have a bucket. Delete it to create a new one.', 'error')
            return redirect(url_for('admin_dashboard'))

        bucket_name = create_user_bucket(admin_user['username'])
        
        # Update DynamoDB
        users_table.update_item(
            Key={'email': admin_user['email']},
            UpdateExpression='SET buckets = :b, active_bucket = :ab',
            ExpressionAttributeValues={
                ':b': [bucket_name],
                ':ab': bucket_name
            }
        )
        
        flash(f'Bucket {bucket_name} created and set as active.', 'success')
        
    except Exception as e:
        logger.error(f"Error creating admin bucket: {str(e)}")
        flash(f"Error creating bucket: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Approve User Route
@app.route('/approve_user/<email>', methods=['POST'])
def approve_user(email):
    if 'user' not in session or session['user'].get('role') != 'admin' or not all(key in session['user'] for key in ['email', 'username']):
        session.clear()
        flash('Invalid or tampered session. Please login again.', 'error')
        return redirect(url_for('login'))

    if not is_valid_email(email):
        flash('Invalid user email.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        user = users_table.get_item(Key={'email': email}).get('Item')
        if not user:
            flash(f"User {email} not found.", 'error')
            return redirect(url_for('admin_dashboard'))

        users_table.update_item(
            Key={'email': email},
            UpdateExpression='SET approved = :approved',
            ExpressionAttributeValues={':approved': True}
        )
        
        # Log the approval action
        if not log_audit_action(
            session['user']['email'],
            'approve_user',
            f"Approved user {email} with username {user.get('username', 'N/A')}"
        ):
            flash("Failed to log user approval.", 'error')
            
        flash(f"User {email} approved successfully.", 'success')
    except ClientError as e:
        logger.error(f"Error approving user {email}: {str(e)}")
        flash(f"Error approving user: {str(e)}", 'error')

    return redirect(url_for('admin_dashboard'))

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_table.get_item(Key={'email': email}).get('Item')
        if user:
            otp = generate_otp()
            session['forgot_email'] = email        
            session['forgot_otp'] = otp
            send_mfa_email(email, otp)
            return jsonify({'success': True, 'message': 'OTP sent successfully.'})
        return jsonify({'success': False, 'message': 'Email not registered.'})
    return render_template('forgot_password.html')

# Forgot Password Verification Route
@app.route('/forgot_verify', methods=['GET', 'POST'])
def forgot_verify():
    if request.method == 'POST':
        otp = request.form.get('otp')
        password = request.form.get('password')
        email = session.get('forgot_email')

        if otp == session.get('forgot_otp'):
            if not password:
                return jsonify({'success': False, 'message': 'Please enter a new password.'})
            
            if not is_strong_password(password):
                return jsonify({'success': False, 'message': 'Password not strong enough.'})

            pw_hash = pbkdf2_sha256.hash(password)
            users_table.update_item(
                Key={'email': email},
                UpdateExpression='SET password=:p',
                ExpressionAttributeValues={':p': pw_hash}
            )
            return jsonify({'success': True, 'message': 'Password reset successful.'})
        else:
            return jsonify({'success': False, 'message': 'Incorrect OTP.'})

    return render_template('forgot_verify.html')

if __name__ == '__main__':
    # Command-line prompt to choose between starting fresh or keeping old data
    print("Flask Application Startup Options:")
    print("1. Keep existing data (sessions and DynamoDB)")
    print("2. Start fresh (clear sessions and reset DynamoDB)")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '2':
        # Clear session data
        clear_session_data()
        # Reset DynamoDB tables 
        reset_dynamodb_tables()
        print("Started fresh: Cleared sessions and reset DynamoDB tables")
    elif choice != '1':
        print("Invalid choice. Keeping existing data by default.")

    # Ensure session directory exists
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    
    app.run(debug=False, host='0.0.0.0', port=5000)