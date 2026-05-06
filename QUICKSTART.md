# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Python
Download and install Python 3.8+ from: https://www.python.org/downloads/
**Important**: Check "Add Python to PATH" during installation

### Step 2: Open Terminal
Open PowerShell or Command Prompt in the project directory:
```bash
cd "c:\work\BCSS\SEM 5\FYP1\FYP_DEGREE"
```

### Step 3: Create Virtual Environment
```bash
python -m venv venv 
venv\Scripts\activate
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Run the Application
```bash
python run.py
```

### Step 6: Open in Browser
Navigate to: **http://localhost:5000**

---

## 📝 First Use

1. Click "Get Started" to register
2. Fill in username, email, and password
3. Log in with your credentials
4. Click "Analyze" in the navigation
5. Upload a PNG, JPG, or BMP image
6. View the analysis results!

---

## 🧪 Testing Steganalysis

### Test with Clean Images
Use any regular photo - the system should show:
- Low confidence scores (< 40%)
- Status: "Clean File"
- Green progress bars

### Test with Hidden Data
You can create test images with hidden data using various steganography tools:

#### Method 1: Using Steghide (Recommended)
```bash
# Create a text file with secret data
echo "This is secret data" > secret.txt

# Hide it in a JPEG image (requires steghide)
steghide embed -cf yourimage.jpg -ef secret.txt -p password

# View info without extracting
steghide info yourimage.jpg
```

#### Method 2: Using OpenStego
```bash
# Download OpenStego from: https://www.openstego.com/
# Use GUI to embed a message file into a cover image
# Save the output as stego-image.png
```

#### Method 3: Using LSB Python Tools
```bash
# Install LSB steganography library
pip install stepic

# Create a simple embedding script
python
>>> from PIL import Image
>>> import stepic
>>> img = Image.open('cover.png')
>>> img_encoded = stepic.encode(img, b'Hidden message here')
>>> img_encoded.save('stego.png', 'PNG')
```

### 🔍 Extraction Process

When you upload an image with hidden data, the system:

1. **Detects Steganography**: Runs LSB, statistical, and ML analysis
2. **Attempts Extraction**: Tries multiple extraction methods automatically:
   - LSB extraction (extracts least significant bits)
   - Pattern-based extraction
   - Statistical anomaly detection
   - Metadata extraction

3. **Displays Results**: Shows extracted data in the analysis view

### 📋 Expected Results for Stego Images

Upload the modified image - the system should show:
- **High confidence scores** (> 50%)
- **Status**: "Suspicious" (red badge)
- **Red/orange progress bars** for detection methods
- **Extracted data section** (if successful):
  - Raw extracted bytes
  - Decoded text (if valid UTF-8)
  - Download button for extracted data
  - Extraction method used

### 💡 Extraction Success Factors

**High Success Rate:**
- LSB-based steganography
- Text-based hidden messages
- PNG and BMP formats
- Uncompressed data

**Lower Success Rate:**
- Encrypted embeddings (without password)
- Highly compressed JPEG
- Multi-layer encryption
- Custom algorithms

### 📥 Accessing Extracted Data

1. Navigate to the **Analysis Details** page
2. Scroll to **"Extracted Data"** section
3. View the decoded content in the text area
4. Click **"Download Extracted Data"** to save as a file
5. Check **Analysis Logs** for extraction method details

---

## 🎯 What to Expect

### Detection Scores Explained
- **LSB Detection**: Checks for bit manipulation
- **Statistical Analysis**: Runs RS analysis and histogram tests
- **ML Detection**: Uses machine learning for pattern recognition

### Overall Confidence
- **0-40%**: Clean file (low risk)
- **41-70%**: Moderate suspicion (review recommended)
- **71-100%**: High probability of hidden data

---

## 📊 Dashboard Features

- **Total Analyses**: Count of all files analyzed
- **Suspicious Files**: Files with hidden data detected
- **Clean Files**: Files that passed all tests
- **Recent Analyses**: Table showing analysis history

Click on any analysis to view:
- Detailed scores for each detection method
- File information (size, dimensions, type)
- Analysis logs showing the detection process
- Download extracted data (if available)

---

## ⚡ Quick Commands

```bash
# Activate virtual environment
venv\Scripts\activate

# Run application
python run.py

# Install new package
pip install package-name
pip freeze > requirements.txt

# Access Python shell with app context
python
>>> from app import create_app, db
>>> app = create_app()
>>> with app.app_context():
...     # Query database here
```

---

## 🆘 Common Issues

**"Python not found"**
- Install Python from python.org
- Make sure "Add to PATH" was checked during installation

**"Module not found"**
- Activate virtual environment: `venv\Scripts\activate`
- Install dependencies: `pip install -r requirements.txt`

**"Port 5000 in use"**
- Change port in run.py: `app.run(debug=True, port=5001)`

**"Can't upload files"**
- Check that `uploads` folder exists
- Ensure you're logged in

---

## 📚 Learn More

- **Full Documentation**: See [README.md](README.md)
- **Setup Guide**: See [SETUP.md](SETUP.md)
- **Project Walkthrough**: See artifacts/walkthrough.md

## 🎓 For Your FYP Report

### Key Points to Document:
1. **Technologies Used**: Python, Flask, SQLAlchemy, NumPy, scikit-learn
2. **Detection Methods**: LSB, RS Analysis, ML-based
3. **Security Features**: OWASP compliance, CSRF protection, password hashing
4. **User Features**: Authentication, file upload, analysis history
5. **Test Results**: Detection accuracy on various steganography tools

### Testing Methodology:
1. Create dataset of clean images
2. Create dataset with embedded data (steghide, LSB tools)
3. Run all images through the system
4. Calculate accuracy metrics:
   - True Positives (correctly detected)
   - True Negatives (correctly identified as clean)
   - False Positives (clean marked as suspicious)
   - False Negatives (hidden data missed)

---

## 🎉 You're Ready!

The application is fully built and ready to use. Just install Python and run `python run.py`!

For detailed information on features and architecture, check the walkthrough document.
