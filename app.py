from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from flask import send_from_directory
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from flask_migrate import Migrate
from datetime import datetime

def generate_user_key():
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    fernet = Fernet(key)
    return fernet.encrypt(file_data)

def generate_salt_based_on_attribute(unique_attribute):
    # Placeholder implementation - replace with your method
    # This is a simplistic approach and not recommended for production use
    return unique_attribute.encode()[:16]  # Ensure 16 bytes length



def derive_key_from_password(password, salt=None):
    """
    Derive a cryptographic key from a password using PBKDF2.

    :param password: The password to derive the key from.
    :param salt: A cryptographic salt. If None, a new salt is generated.
    :return: A base64 encoded key.
    """
    if salt is None:
        salt = os.urandom(16)

    # Key derivation function setup
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)  # Return only the key


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\Omar\\Desktop\\CryptoWebsite\\uploads'  # Folder for storing uploaded files
db = SQLAlchemy(app)
migrate = Migrate(app, db)



class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_name = db.Column(db.String(300), nullable=False)
    salt = db.Column(db.String(64))  # Example: storing the salt as a string
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Add a timestamp column

    # Define relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_files')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_files')



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    key = db.Column(db.String(200), nullable=False)  # Encryption key for the user

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        key = Fernet.generate_key().decode()  # Generate a unique encryption key for each user
        new_user = User(username=username, password=password, key=key)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Store user id in session
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    received_files = SharedFile.query.filter_by(recipient_id=user_id).all()
    sent_files_query = SharedFile.query.filter_by(sender_id=user_id).all()

    # Create a new list for sent files with modified file names
    sent_files = []
    for file in sent_files_query:
        modified_file = {
            'file_name': f"{file.file_name}",
            'recipient_username': file.recipient.username,  # Include recipient's username
            'id': file.id
        }
        sent_files.append(modified_file)

    return render_template('dashboard.html', received_files=received_files, sent_files=sent_files)


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        recipient_username = request.form['recipient']
        recipient = User.query.filter_by(username=recipient_username).first()
        sender = User.query.get(session['user_id'])

        if recipient:
            # Encrypt the file with the recipient's key
            fernet = Fernet(recipient.key.encode())
            encrypted_data = fernet.encrypt(file.read())
            filename = secure_filename(file.filename)
            encrypted_filename = f"{filename}.enc"  # Update the filename here
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            # Encrypt and save for sender
            sender_key = derive_key_from_password(sender.password)
            fernet_sender = Fernet(sender_key)
            file.seek(0)  # Reset file pointer to the beginning
            encrypted_data_sender = fernet_sender.encrypt(file.read())
            encrypted_filename_sender = f"{filename}_sender.enc"  # Update the filename here
            file_path_sender = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename_sender)
            with open(file_path_sender, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data_sender)    

            # Create a new record for the shared file with the updated filename
            new_file = SharedFile(sender_id=session['user_id'], recipient_id=recipient.id, file_name=encrypted_filename)
            db.session.add(new_file)
            db.session.commit()

            flash("File encrypted and sent.")
            return redirect(url_for('dashboard'))
        else:
            flash("Recipient not found.")
    return render_template('upload.html')





@app.route('/download/received/<int:file_id>')
def download_received_file(file_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("User not logged in.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    file_record = SharedFile.query.get(file_id)

    if not file_record or file_record.recipient_id != user_id:
        flash("File not found or access denied.")
        return redirect(url_for('dashboard'))

    fernet = Fernet(user.key)  # user.key should be the recipient's key

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.file_name)
    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        flash(f"An error occurred: {e}")
        return redirect(url_for('dashboard'))

    # Remove the .enc extension for the downloaded file
    original_file_name = file_record.file_name
    if original_file_name.endswith('.enc'):
        original_file_name = original_file_name[:-4]

    response = make_response(decrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename="{original_file_name}"'
    response.headers['Content-Type'] = 'application/octet-stream'
    return response

@app.route('/download/sent/<int:file_id>')
def download_sent_file(file_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("User not logged in.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    file_record = SharedFile.query.get(file_id)

    if not file_record or file_record.sender_id != user_id:
        flash("File not found or access denied.")
        return redirect(url_for('dashboard'))

    # Generate a consistent salt based on a unique attribute
    # Replace 'some_unique_attribute' with an actual unique attribute from your model
    # Replace 'some_unique_attribute' with an actual unique attribute from your model
    salt = os.urandom(16)  # Generate a random 16-byte salt
    sender_key = derive_key_from_password(user.password, salt)
    fernet = Fernet(sender_key)

    filename = f"{file_record.file_name}_sender"  # Adjust as per your naming convention
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        # You can also flash an error message if needed
        return redirect(url_for('dashboard'))  # Redirect back to the dashboard or handle the error as needed

    # Provide a custom message as a default value
    encoded_data = b''

    response = make_response(encrypted_data)
    response.headers['Content-Disposition'] = f'attachment; filename={file_record.file_name}'
    response.headers['Content-Type'] = 'application/octet-stream'
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
