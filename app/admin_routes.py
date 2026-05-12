from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import User, Analysis, AnalysisLog
from datetime import datetime, timedelta
from sqlalchemy import func

admin = Blueprint('admin', __name__, url_prefix='/admin')


# ── Guard decorator ──────────────────────────────────────────────────────────
def admin_required(f):
    """Decorator: only allow users with is_admin=True."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('main.login'))
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ────────────────────────────────────────────────────────────────
@admin.route('/')
@login_required
@admin_required
def dashboard():
    """Admin overview with system-wide stats and recent activity."""
    total_users     = User.query.count()
    total_analyses  = Analysis.query.count()
    suspicious      = Analysis.query.filter_by(has_hidden_data=True).count()
    files_extracted = Analysis.query.filter_by(extracted_data_available=True).count()
    locked_users    = User.query.filter(User.locked_until.isnot(None)).count()

    # Recent 10 analyses across all users
    recent_analyses = (
        Analysis.query
        .join(User)
        .order_by(Analysis.analyzed_at.desc())
        .limit(10)
        .all()
    )

    # User registrations per day for the last 7 days
    today = datetime.utcnow().date()
    reg_labels, reg_data = [], []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = User.query.filter(
            func.date(User.created_at) == day
        ).count()
        reg_labels.append(day.strftime('%b %d'))
        reg_data.append(count)

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        total_analyses=total_analyses,
        suspicious=suspicious,
        files_extracted=files_extracted,
        locked_users=locked_users,
        recent_analyses=recent_analyses,
        reg_labels=reg_labels,
        reg_data=reg_data,
    )


# ── User Management ──────────────────────────────────────────────────────────
@admin.route('/users')
@login_required
@admin_required
def users():
    """List all users with management actions."""
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=all_users)


@admin.route('/users/<int:user_id>/toggle-lock', methods=['POST'])
@login_required
@admin_required
def toggle_lock(user_id):
    """Lock or unlock a user account."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot lock your own account.', 'warning')
        return redirect(url_for('admin.users'))

    if user.is_locked_out():
        user.locked_until = None
        user.failed_login_attempts = 0
        flash(f'Account for "{user.username}" has been unlocked.', 'success')
    else:
        user.locked_until = datetime.utcnow() + timedelta(days=3650)  # effectively permanent
        flash(f'Account for "{user.username}" has been locked.', 'warning')

    db.session.commit()
    return redirect(url_for('admin.users'))


@admin.route('/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    """Grant or revoke admin privileges."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot change your own admin status.', 'warning')
        return redirect(url_for('admin.users'))

    user.is_admin = not user.is_admin
    db.session.commit()
    status = 'granted' if user.is_admin else 'revoked'
    flash(f'Admin privileges {status} for "{user.username}".', 'success')
    return redirect(url_for('admin.users'))


@admin.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user and all their analyses."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account from the admin panel.', 'danger')
        return redirect(url_for('admin.users'))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{username}" and all their data have been deleted.', 'success')
    return redirect(url_for('admin.users'))


# ── Analyses ─────────────────────────────────────────────────────────────────
@admin.route('/analyses')
@login_required
@admin_required
def analyses():
    """List all analyses across all users."""
    page = request.args.get('page', 1, type=int)
    pagination = (
        Analysis.query
        .join(User)
        .order_by(Analysis.analyzed_at.desc())
        .paginate(page=page, per_page=20, error_out=False)
    )
    return render_template('admin/analyses.html', pagination=pagination)
