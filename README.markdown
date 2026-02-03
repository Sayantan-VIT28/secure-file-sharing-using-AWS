# Secure File Sharing Application

## Overview

This is a Flask-based web application for secure file sharing, utilizing AWS services for storage, email notifications, and database management. The application supports user registration, multi-factor authentication (MFA), file encryption/decryption, and admin functionalities like user approval and bucket management.

## Features

- **User Registration and Login**: Users can register as "user" or "admin" with email-based MFA.
- **File Sharing**: Upload, encrypt, and share files securely via AWS S3, with download links sent via AWS SES.
- **File Decryption**: Decrypt shared files using a provided password.
- **Admin Dashboard**: Manage users, approve bucket requests, view audit logs, and monitor storage usage.
- **AWS Integration**: Uses S3 for file storage, SES for email notifications, and DynamoDB for user and share data.
- **Security**: Implements strong password validation, session management, and audit logging.

## Prerequisites

To run this application locally or deploy it, ensure the following are installed and configured:

### Software Requirements

- **Python**: Version 3.9 or higher.
- **Git**: For version control and cloning the repository.
- **GitHub Desktop** (optional): For managing Git operations.
- **AES Encryption Tool**: A custom AES encryption executable (not included in this repository). Set the path in the `AES_EXE_PATH` environment variable.
- **Web Browser**: For accessing the web interface.

### Python Dependencies

Install the required Python packages using pip:

```bash
pip install flask flask-session boto3 botocore werkzeug passlib shutil logging re secrets time tempfile zipfile datetime string random subprocess uuid os render_template request redirect url_for session send_file flash jsonify secure_filename pbkdf2_sha256 BytesIO
```

### AWS Integrations

- **AWS Account**: Create an AWS account at aws.amazon.com.
- **AWS CLI**: Install and configure the AWS CLI for credential management:

  ```bash
  pip install awscli
  aws configure
  ```
  Provide your AWS Access Key ID, Secret Access Key, and default region (e.g., `us-west-2`).
- **AWS S3**: Ensure you have permissions to create and manage S3 buckets.
- **AWS SES**: Verify an email address (e.g., `your_email`) in SES for sending emails. Update `SES_CONSTANT_SENDER` in `app.py`. Note: All emails should either be registered in AWS  SES else opt out from AWS sandbox by sending an email to the aws provider.
- **AWS DynamoDB**: Create the following tables:
  - `UsersTable`: Partition key `email` (string).
  - `SharesTable`: Partition key `share_id` (string), with a global secondary index `sender-email-index` on `sender_email` (string).
  - `RequestsTable`: Partition key `request_id` (string).
  - `LogsTable`: Partition key `log_id` (string).
  - `SessionsTable`: Partition key `id` (string) (optional, for session management).
- **AWS Credentials**: Store credentials in `~/.aws/credentials` or set environment variables:

  ```bash
  export AWS_ACCESS_KEY_ID='your-access-key-id'
  export AWS_SECRET_ACCESS_KEY='your-secret-access-key'
  export AWS_DEFAULT_REGION='us-west-2'
  ```

### Environment Variables

Set the following environment variables:

- `AES_EXE_PATH`: Path to the AES encryption executable (e.g., `/secure/path/to/encryptor`).
- `OTP_EXPIRATION_SECONDS`: OTP expiration time in seconds (default: 600).
- `FLASK_SECRET_KEY`: Secret key for Flask sessions (e.g., a 32-byte hex string).

  ```bash
  export FLASK_SECRET_KEY='placeholder_secret_key_1234567890abcdef'
  ```

🛠 Cross-Language Integration: Python & C++
To balance developer productivity with high-performance cryptography, this application utilizes a Hybrid Architecture:

Frontend/Logic (Python/Flask): Handles the web interface, AWS SDK (Boto3) calls, and user session management.

Cryptographic Core (C++): A compiled C++ executable handles AES-GCM (Galois/Counter Mode). This ensures authenticated encryption that is significantly faster than standard interpreted Python libraries.

The Bridge: The Flask server communicates with the C++ engine using the subprocess module, passing file paths and encryption keys as secure arguments to the compiled binary.

Workflow:

User uploads a file via the Flask UI.

Flask triggers the C++ engine: subprocess.run([AES_EXE_PATH, mode, file_path, key]).

The C++ engine encrypts/decrypts the file at the hardware level.

Flask handles the resulting secure file and uploads it to AWS S3.

## Setup Instructions

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   Create a `requirements.txt` file with:

   ```
   flask
   flask-session
   boto3
   botocore
   werkzeug
   passlib
   ```

3. **Configure AWS**:

   - Set up AWS credentials via `aws configure` or environment variables.
   - Verify an SES email address and update `SES_CONSTANT_SENDER` in `app.py`.
   - Ensure DynamoDB tables are created with the specified schema.

4. **Set Up AES Tool**:

   - Place the AES encryption executable in a secure location.
   - Set the `AES_EXE_PATH` environment variable to its path.

5. **Run the Application**:

   ```bash
   python app.py
   ```

   - On startup, choose:
     - `1` to keep existing data.
     - `2` to clear sessions and reset DynamoDB tables (use with caution).
   - Access the app at `http://localhost:5000`.

## Usage

- **Register**: Navigate to `/register` to create a user or admin account. Admins require a master password (`placeholder_admin_123`).
- **Login**: Access `/login` and verify with MFA OTP sent to your email.
- **Dashboard**:
  - **Users**: Upload, encrypt, and share files, or decrypt files with a password.
  - **Admins**: Approve users, manage buckets, view audit logs, and monitor storage.
- **File Sharing**: Select up to 5 files, provide a recipient email and encryption password (starting with `@`), and verify with MFA.
- **Bucket Management**: Request or approve S3 buckets for storage (5GB limit per user).

## Security Notes

- **Sensitive Data**: All sensitive data (e.g., emails, passwords, paths) has been replaced with placeholders (e.g., `your_email`, `placeholder_admin_123`, `/secure/path/to/encryptor`).
- **Environment Variables**: Store sensitive configurations in environment variables or a `.env` file (excluded via `.gitignore`).
- **AWS Credentials**: Never commit AWS credentials or `.env` files to Git.
- **Session Security**: Uses Flask-Session with filesystem storage and secure cookie settings.

-**Watch the mp4 file**
