# Steganalysis Detection System

A web-based forensic analysis tool for detecting and extracting hidden data in multimedia files using advanced steganalysis techniques.

## Features

- **Multiple Detection Techniques**:
  - LSB (Least Significant Bit) Detection
  - Statistical Analysis (Chi-square, RS Analysis)
  - Machine Learning-based Detection

- **Data Extraction**:
  - Support for known steganography tools (steghide, LSB-based)
  - Automated payload extraction

- **Security Compliant**:
  - OWASP Application Security Guidelines
  - Protection against SQL Injection, XSS, CSRF
  - Secure file upload handling

- **User Features**:
  - User authentication and authorization
  - Analysis history and logs
  - Detailed file metadata storage

## Supported File Types

- PNG
- JPG/JPEG
- BMP

## Installation

### Requirements

- Python 3.8+
- pip

### Setup

```bash
# Clone the repository
cd FYP_DEGREE

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
flask db init
flask db migrate
flask db upgrade

# Run the application
python run.py
```

## Usage

1. Register a new account or login
2. Upload an image file (PNG, JPG, BMP)
3. View analysis results showing:
   - Detection confidence scores
   - Steganalysis technique results
   - Extracted hidden data (if any)
4. Access analysis history in your dashboard

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite
- **Authentication**: Flask-Login
- **Security**: Flask-WTF, Werkzeug
- **Image Processing**: Pillow, NumPy, scikit-learn
- **Steganalysis**: Custom algorithms + steghide integration

## Project Structure

```
FYP_DEGREE/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── forms.py
│   ├── steganalysis/
│   │   ├── lsb_detector.py
│   │   ├── statistical_analysis.py
│   │   ├── ml_detector.py
│   │   └── extractor.py
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       └── analyze.html
├── uploads/
├── config.py
├── run.py
└── requirements.txt
```

## Security Features

- Password hashing with Werkzeug
- CSRF protection on all forms
- File type validation
- File size limits
- Secure filename sanitization
- SQL injection prevention via SQLAlchemy ORM
- XSS protection via template escaping

## License

Educational Project - FYP

## Author

Ameer Idris - Final Year Project 2026
