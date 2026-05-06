from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, send_file
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import User, Analysis, AnalysisLog
from app.forms import LoginForm, RegistrationForm, UploadForm
from app.steganalysis import LSBDetector, StatisticalAnalyzer, MLDetector, DataExtractor
from datetime import datetime
import os
import json

main = Blueprint('main', __name__)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@main.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('main.login'))
        
        login_user(user, remember=form.remember_me.data)
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        flash('Login successful!', 'success')
        
        # Redirect to next page if specified
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('main.dashboard'))
    
    return render_template('login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('register.html', form=form)

@main.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing analysis history"""
    page = request.args.get('page', 1, type=int)
    analyses = Analysis.query.filter_by(user_id=current_user.id)\
                             .order_by(Analysis.analyzed_at.desc())\
                             .paginate(page=page, per_page=10, error_out=False)
    
    # Statistics
    total_analyses = Analysis.query.filter_by(user_id=current_user.id).count()
    suspicious_files = Analysis.query.filter_by(user_id=current_user.id, has_hidden_data=True).count()
    
    stats = {
        'total_analyses': total_analyses,
        'suspicious_files': suspicious_files,
        'clean_files': total_analyses - suspicious_files
    }
    
    return render_template('dashboard.html', analyses=analyses, stats=stats)

@main.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    """Upload and analyze file"""
    form = UploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        
        if file and allowed_file(file.filename):
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Create unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            unique_filename = f"{current_user.id}_{timestamp}_{filename}"
            
            # Save file
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            # Perform analysis
            analysis_result = perform_analysis(filepath, filename, current_user.id)
            
            flash('Analysis completed!', 'success')
            return redirect(url_for('main.view_analysis', analysis_id=analysis_result['id']))
        else:
            flash('Invalid file type. Only PNG, JPG, and BMP files are allowed.', 'danger')
    
    return render_template('analyze.html', form=form)

@main.route('/analysis/<int:analysis_id>')
@login_required
def view_analysis(analysis_id):
    """View detailed analysis results"""
    analysis = Analysis.query.get_or_404(analysis_id)
    
    # Check if user owns this analysis
    if analysis.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get logs
    logs = AnalysisLog.query.filter_by(analysis_id=analysis_id)\
                            .order_by(AnalysisLog.timestamp.asc())\
                            .all()
    
    return render_template('view_analysis.html', analysis=analysis, logs=logs)

@main.route('/download/<int:analysis_id>')
@login_required
def download_extracted(analysis_id):
    """Download extracted data"""
    analysis = Analysis.query.get_or_404(analysis_id)
    
    # Check permissions
    if analysis.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    if not analysis.extracted_data_available or not analysis.extracted_data_path:
        flash('No extracted data available.', 'warning')
        return redirect(url_for('main.view_analysis', analysis_id=analysis_id))
    
    if not os.path.exists(analysis.extracted_data_path):
        flash('Extracted file not found.', 'error')
        return redirect(url_for('main.view_analysis', analysis_id=analysis_id))
    
    return send_file(analysis.extracted_data_path, as_attachment=True)

@main.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    """Serve an uploaded image file (for thumbnail display)"""
    upload_folder = current_app.config['UPLOAD_FOLDER']
    return send_file(os.path.join(upload_folder, filename))


@main.route('/analysis/<int:analysis_id>/delete', methods=['POST'])
@login_required
def delete_analysis(analysis_id):
    """Delete an analysis record and its associated files"""
    analysis = Analysis.query.get_or_404(analysis_id)

    # Security: only the owner can delete
    if analysis.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Remove uploaded image file from disk
    if analysis.file_path and os.path.exists(analysis.file_path):
        try:
            os.remove(analysis.file_path)
        except OSError:
            pass  # File already gone — that's fine

    # Remove extracted data file from disk
    if analysis.extracted_data_path and os.path.exists(analysis.extracted_data_path):
        try:
            os.remove(analysis.extracted_data_path)
        except OSError:
            pass

    # Delete logs first (foreign-key child rows), then the analysis
    AnalysisLog.query.filter_by(analysis_id=analysis_id).delete()
    db.session.delete(analysis)
    db.session.commit()

    flash(f'Analysis for "{analysis.original_filename}" has been deleted.', 'success')
    return redirect(url_for('main.dashboard'))

def perform_analysis(filepath, original_filename, user_id):
    """
    Perform complete steganalysis on uploaded file
    """
    from PIL import Image
    
    # Create analysis record
    analysis = Analysis(
        user_id=user_id,
        filename=os.path.basename(filepath),
        original_filename=original_filename,
        file_path=filepath
    )
    
    try:
        # Get file info
        file_stat = os.stat(filepath)
        analysis.file_size = file_stat.st_size
        analysis.file_type = original_filename.rsplit('.', 1)[1].lower()
        
        # Get image info
        img = Image.open(filepath)
        analysis.image_width = img.width
        analysis.image_height = img.height
        analysis.image_mode = img.mode
        
        # Log start
        log_analysis(analysis, 'INFO', 'Analysis started', {'file': original_filename})
        
        # Initialize detectors
        lsb_detector = LSBDetector()
        statistical_analyzer = StatisticalAnalyzer()
        ml_detector = MLDetector()
        data_extractor = DataExtractor()
        
        # Run LSB detection
        log_analysis(analysis, 'INFO', 'Running LSB detection', {})
        lsb_result = lsb_detector.analyze(filepath)
        analysis.lsb_detection_score = lsb_result.get('score', 0)
        log_analysis(analysis, 'INFO', 'LSB detection completed', 
                    {'score': lsb_result.get('score', 0)})
        
        # Run statistical analysis
        log_analysis(analysis, 'INFO', 'Running statistical analysis', {})
        stat_result = statistical_analyzer.analyze(filepath)
        analysis.statistical_score = stat_result.get('score', 0)
        log_analysis(analysis, 'INFO', 'Statistical analysis completed',
                    {'score': stat_result.get('score', 0)})
        
        # Run ML detection
        log_analysis(analysis, 'INFO', 'Running ML detection', {})
        ml_result = ml_detector.analyze(filepath)
        analysis.ml_detection_score = ml_result.get('score', 0)
        log_analysis(analysis, 'INFO', 'ML detection completed',
                    {'score': ml_result.get('score', 0)})
        
        # Calculate overall confidence
        scores = [
            analysis.lsb_detection_score or 0,
            analysis.statistical_score or 0,
            analysis.ml_detection_score or 0
        ]
        analysis.confidence_score = sum(scores) / len(scores)
        
        # Determine if hidden data is present
        analysis.has_hidden_data = analysis.confidence_score > 50
        
        # Always attempt data extraction — even low-confidence images may have hidden data
        log_analysis(analysis, 'INFO', 'Attempting data extraction', {})

        extract_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'extracted')
        os.makedirs(extract_dir, exist_ok=True)

        extraction_result = data_extractor.extract(filepath, extract_dir)

        if extraction_result.get('extracted'):
            analysis.extracted_data_available = True
            analysis.extracted_data_path = extraction_result.get('output_path')
            analysis.extraction_method = extraction_result.get('method')
            analysis.extracted_data_preview = extraction_result.get('data_preview')
            analysis.extracted_data_type = extraction_result.get('data_type')
            analysis.extracted_data_size = extraction_result.get('data_size')
            analysis.hidden_filename = extraction_result.get('hidden_filename')

            # If we successfully extracted data, mark as suspicious if not already
            if not analysis.has_hidden_data:
                analysis.has_hidden_data = True
                analysis.confidence_score = max(analysis.confidence_score or 0, 60.0)

            log_analysis(analysis, 'WARNING', 'Data extraction successful',
                       {'method': extraction_result.get('method'),
                        'type': extraction_result.get('data_type'),
                        'size': extraction_result.get('data_size'),
                        'hidden_file': extraction_result.get('hidden_filename')})
        else:
            log_analysis(analysis, 'INFO', 'No extractable data found', {})
        
        # Create analysis notes
        notes = []
        notes.append(f"Overall Confidence: {analysis.confidence_score:.2f}%")
        notes.append(f"LSB Score: {analysis.lsb_detection_score:.2f}%")
        notes.append(f"Statistical Score: {analysis.statistical_score:.2f}%")
        notes.append(f"ML Score: {analysis.ml_detection_score:.2f}%")
        
        if analysis.has_hidden_data:
            notes.append("ALERT: Hidden data detected!")
        else:
            notes.append("File appears clean.")
        
        analysis.analysis_notes = '\n'.join(notes)
        
        log_analysis(analysis, 'INFO', 'Analysis completed successfully', {})
        
    except Exception as e:
        log_analysis(analysis, 'ERROR', f'Analysis failed: {str(e)}', {})
        analysis.analysis_notes = f"Error during analysis: {str(e)}"
        analysis.confidence_score = 0
    
    # Save to database
    db.session.add(analysis)
    db.session.commit()
    
    return {'id': analysis.id, 'success': True}

def log_analysis(analysis, level, message, details):
    """
    Log analysis operation
    """
    log = AnalysisLog(
        analysis_id=analysis.id if analysis.id else None,
        log_level=level,
        message=message,
        details=json.dumps(details) if details else None
    )
    
    if analysis.id:
        db.session.add(log)
        db.session.commit()
