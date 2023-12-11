# Secure-File-Sharing-Website
Cryptographic Secure File Sharing Application
Introduction
This application is a secure file-sharing platform built using Flask, SQLAlchemy, and the Cryptography library. It allows users to securely upload, share, and download files, ensuring data confidentiality and integrity through advanced cryptographic techniques.

Features
User Authentication: Secure login system with hashed passwords.
File Encryption/Decryption: Files are encrypted using recipient-specific keys before upload and decrypted upon download.
Key Management: Each user has a unique encryption key for securing files.
Secure File Storage: Files are stored securely on the server with encryption.
Installation
To set up the project locally, follow these steps:

Clone the Repository

bash
Copy code
git clone [https://github.com/your-username/your-repository.git](https://github.com/samiirspot/Secure-File-Sharing-Website.git)
cd your-repository
Set Up a Virtual Environment (Optional but recommended)

bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
Install Dependencies

bash
Copy code
pip install -r requirements.txt
Initialize the Database

bash
Copy code
flask db upgrade
Run the Application

bash
Copy code
flask run
Usage
After starting the application, navigate to http://localhost:5000 in your web browser. You can register a new user account, log in, and start sharing files securely.

Contributing
Contributions to this project are welcome! Please fork the repository and submit a pull request with your changes.
