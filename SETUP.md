# Installation and Setup Guide

## Prerequisites

Before running this application, ensure you have:
- Python 3.8 or higher installed
- pip (Python package manager)

## Installation Steps

### 1. Install Python

If you don't have Python installed:
- Download Python from: https://www.python.org/downloads/
- During installation, **make sure to check "Add Python to PATH"**
- Verify installation:
  ```bash
  python --version
  ```

### 2. Create Virtual Environment

```bash
# Navigate to project directory
cd "c:\work\BCSS\SEM 5\FYP1\FYP_DEGREE"

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

### 4. Configure Environment

The `.env` file has been created for you. You can customize it if needed:
- Edit `.env` to set your own SECRET_KEY
- Default database is SQLite (no additional setup required)

### 5. Initialize Database

```bash
# Create database tables
python run.py
```

The database will be created automatically when you run the application for the first time.

### 6. Run the Application

```bash
# Start the Flask development server
python run.py
```

The application will be available at: **http://localhost:5000**

## First Time Use

1. Navigate to http://localhost:5000
2. Click "Get Started" or "Register"
3. Create your account
4. Log in with your credentials
5. Upload an image file for analysis

## Testing the Application

### Using Sample Images

To test the steganalysis capabilities:

1. **Clean Image**: Use any regular photo from your computer
2. **Image with Hidden Data**: You can create one using steghide:
   ```bash
   # Install steghide (optional)
   # On Windows: Download from http://steghide.sourceforge.net/
   
   # Hide data in image
   steghide embed -cf image.jpg -ef secret.txt -p password
   ```

### Expected Results

- **LSB Detection Score**: 0-100% (higher = more suspicious)
- **Statistical Score**: 0-100% (higher = more suspicious)
- **ML Detection Score**: 0-100% (higher = more suspicious)
- **Overall Confidence**: Average of all three scores

Scores above 50% typically indicate suspicious files.

## Troubleshooting

### Issue: "Module not found" errors
**Solution**: Make sure you've activated the virtual environment and installed all dependencies:
```bash
venv\Scripts\activate
pip install -r requirements.txt
```

### Issue: Database errors
**Solution**: Delete the `steganalysis.db` file and restart the application to recreate it.

### Issue: Port 5000 already in use
**Solution**: The run.py file uses port 5000. Either:
- Stop the process using port 5000
- Or modify `run.py` to use a different port:
  ```python
  app.run(debug=True, host='0.0.0.0', port=5001)
  ```

### Issue: File upload fails
**Solution**: Ensure the `uploads` directory exists and has write permissions.

## Development Tips

### Accessing the Database

You can inspect the SQLite database using:
- DB Browser for SQLite: https://sqlitebrowser.org/
- Or use Python:
  ```python
  python
  >>> from app import create_app, db
  >>> from app.models import User, Analysis
  >>> app = create_app()
  >>> with app.app_context():
  ...     users = User.query.all()
  ...     print(users)
  ```

### Viewing Logs

Analysis logs are stored in the database. You can view them:
- Through the web interface (Analysis Details page)
- Or query the `AnalysisLog` table directly

### Adding New Detection Methods

To add new steganalysis techniques:
1. Create a new detector class in `app/steganalysis/`
2. Implement the `analyze()` method
3. Add it to `app/routes.py` in the `perform_analysis()` function

## Security Notes

- Change the SECRET_KEY in `.env` before deploying to production
- Never commit `.env` to version control
- For production deployment:
  - Use a production WSGI server (gunicorn, waitress)
  - Enable HTTPS
  - Use a production database (PostgreSQL, MySQL)
  - Set `SESSION_COOKIE_SECURE = True` in config.py

## Project Structure

```
FYP_DEGREE/
├── app/
│   ├── __init__.py          # App initialization
│   ├── models.py            # Database models
│   ├── routes.py            # URL routes and views
│   ├── forms.py             # WTForms
│   ├── steganalysis/        # Detection modules
│   │   ├── lsb_detector.py
│   │   ├── statistical_analysis.py
│   │   ├── ml_detector.py
│   │   └── extractor.py
│   ├── static/
│   │   └── css/style.css    # Styling
│   └── templates/           # HTML templates
├── uploads/                 # Uploaded files
├── config.py                # Configuration
├── run.py                   # Application entry point
├── requirements.txt         # Dependencies
└── README.md               # Documentation
```

## Next Steps

After getting the application running:
1. Test with various image types (PNG, JPG, BMP)
2. Experiment with different steganography tools
3. Analyze the detection accuracy
4. Document your findings
5. Consider adding more detection techniques

## Support

For issues or questions:
- Check the README.md for general information
- Review the code comments for implementation details
- Refer to Flask documentation: https://flask.palletsprojects.com/
