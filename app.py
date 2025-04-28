# app.py
import os
import secrets
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, session
from werkzeug.utils import secure_filename
import io
from asd import SecureFileSystem, logger

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For flash messages and sessions

# Initialize the secure file system
secure_fs = SecureFileSystem()

# Session management for passwords
@app.before_request
def before_request():
    # Set default password if not in session
    if 'password' not in session:
        session['password'] = "default_password"

@app.route('/')
def index():
    # Get list of files from secure file system
    files = secure_fs.list_files()
    # Get current password from session
    current_password = session.get('password', 'default_password')
    return render_template('index.html', files=files, current_password=current_password)

@app.route('/set_password', methods=['POST'])
def set_password():
    password = request.form.get('password', 'default_password')
    session['password'] = password
    flash('Password updated successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if a file was uploaded
    if 'file' not in request.files:
        flash('No file part!', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    
    # Check if a file was selected
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('index'))
    
    # Get password from session or form
    password = session.get('password', 'default_password')
    override_password = request.form.get('override_password')
    if override_password:
        password = override_password
    
    try:
        # Read the file data
        file_data = file.read()
        
        # Process the file
        result = secure_fs.process_file_data(file_data, file.filename, password)
        
        if result["status"] == "success":
            # Log the encryption key used
            logger.info(f"File '{file.filename}' encrypted with key: {password}")
            flash(f"File '{file.filename}' uploaded and encrypted successfully!", 'success')
        else:
            flash(f"Error uploading file: {result['message']}", 'danger')
        
        return redirect(url_for('index'))
    
    except Exception as e:
        flash(f"Error: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/download/<secure_id>', methods=['GET'])
def download_file(secure_id):
    # Get password from session or query parameter
    password = request.args.get('password', session.get('password', 'default_password'))
    
    try:
        # Retrieve and decrypt the file
        file_data, original_name = secure_fs.retrieve_file(secure_id, password)
        
        if file_data is None:
            flash('File not found or decryption failed. Check your password.', 'danger')
            return redirect(url_for('index'))
        
        # Log the decryption key used
        logger.info(f"File '{original_name}' (ID: {secure_id}) decrypted with key: {password}")
        
        # Send the file for download
        return send_file(
            io.BytesIO(file_data),
            download_name=original_name,
            as_attachment=True
        )
    
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<secure_id>', methods=['POST'])
def delete_file(secure_id):
    try:
        # Delete the file
        success = secure_fs.delete_file(secure_id)
        
        if success:
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found or deletion failed.', 'danger')
        
        return redirect(url_for('index'))
    
    except Exception as e:
        flash(f"Error deleting file: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/view_logs')
def view_logs():
    try:
        # Read the last 100 lines from the log file
        log_file = "secure_file_system.log"
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                # Get the last 100 lines
                lines = f.readlines()[-100:]
                logs = ''.join(lines)
        else:
            logs = "Log file not found."
        
        return render_template('logs.html', logs=logs)
    
    except Exception as e:
        flash(f"Error reading logs: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/file_details/<secure_id>')
def file_details(secure_id):
    # Get file info from index
    files = secure_fs.list_files()
    file_info = None
    
    for file in files:
        if file['secure_id'] == secure_id:
            file_info = file
            break
    
    if file_info is None:
        flash('File not found.', 'danger')
        return redirect(url_for('index'))
    
    # Get current password from session
    current_password = session.get('password', 'default_password')
    
    return render_template('file_details.html', file=file_info, current_password=current_password)

@app.template_filter('format_size')
def format_size(size_bytes):
    """Format file size in a human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Create the template files
    with open('templates/layout.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Secure File System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.3/font/bootstrap-icons.css">
    <style>
        body {
            padding-top: 20px;
            padding-bottom: 20px;
        }
        .file-list {
            max-height: 500px;
            overflow-y: auto;
        }
        .password-toggle {
            cursor: pointer;
        }
        .log-container {
            max-height: 600px;
            overflow-y: auto;
            background-color: #f8f9fa;
            font-family: monospace;
            white-space: pre-wrap;
            padding: 15px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="d-flex flex-wrap justify-content-center py-3 mb-4 border-bottom">
            <a href="/" class="d-flex align-items-center mb-3 mb-md-0 me-md-auto text-dark text-decoration-none">
                <i class="bi bi-shield-lock me-2" style="font-size: 2rem;"></i>
                <span class="fs-4">Secure File System</span>
            </a>
            <ul class="nav nav-pills">
                <li class="nav-item"><a href="/" class="nav-link {% if request.path == '/' %}active{% endif %}">Home</a></li>
                <li class="nav-item"><a href="/view_logs" class="nav-link {% if request.path == '/view_logs' %}active{% endif %}">Logs</a></li>
            </ul>
        </header>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
        
        <footer class="d-flex flex-wrap justify-content-between align-items-center py-3 my-4 border-top">
            <div class="col-md-4 d-flex align-items-center">
                <span class="text-muted">© 2025 Secure File System</span>
            </div>
        </footer>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Password toggle functionality
            document.querySelectorAll('.password-toggle').forEach(function(element) {
                element.addEventListener('click', function() {
                    const passwordField = document.getElementById(this.dataset.target);
                    const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
                    passwordField.setAttribute('type', type);
                    
                    // Toggle icon
                    if (type === 'text') {
                        this.innerHTML = '<i class="bi bi-eye-slash"></i>';
                    } else {
                        this.innerHTML = '<i class="bi bi-eye"></i>';
                    }
                });
            });
        });
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>''')
    
    with open('templates/index.html', 'w') as f:
        f.write('''{% extends "layout.html" %}

{% block content %}
<div class="row mb-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-primary text-white">
                <h5 class="mb-0"><i class="bi bi-key me-2"></i>Encryption Password</h5>
            </div>
            <div class="card-body">
                <form action="/set_password" method="post" class="mb-0">
                    <div class="input-group">
                        <input type="password" class="form-control" id="globalPassword" name="password" value="{{ current_password }}" required>
                        <span class="input-group-text password-toggle" data-target="globalPassword">
                            <i class="bi bi-eye"></i>
                        </span>
                        <button type="submit" class="btn btn-primary">Set Password</button>
                    </div>
                    <div class="form-text">This password will be used to encrypt and decrypt files.</div>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-success text-white">
                <h5 class="mb-0"><i class="bi bi-upload me-2"></i>Upload File</h5>
            </div>
            <div class="card-body">
                <form action="/upload" method="post" enctype="multipart/form-data">
                    <div class="mb-3">
                        <label for="file" class="form-label">Select File</label>
                        <input type="file" class="form-control" id="file" name="file" required>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="overridePasswordCheck">
                            <label class="form-check-label" for="overridePasswordCheck">
                                Override password for this file
                            </label>
                        </div>
                    </div>
                    <div class="mb-3" id="overridePasswordField" style="display: none;">
                        <label for="overridePassword" class="form-label">Custom Password</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="overridePassword" name="override_password">
                            <span class="input-group-text password-toggle" data-target="overridePassword">
                                <i class="bi bi-eye"></i>
                            </span>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-success">Upload</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header bg-dark text-white">
        <h5 class="mb-0"><i class="bi bi-files me-2"></i>Secured Files</h5>
    </div>
    <div class="card-body p-0">
        <div class="table-responsive file-list">
            <table class="table table-hover table-striped mb-0">
                <thead>
                    <tr>
                        <th>Original Name</th>
                        <th>File Type</th>
                        <th>Upload Time</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% if files %}
                        {% for file in files %}
                            <tr>
                                <td>{{ file.original_name }}</td>
                                <td>{{ file.file_type }}</td>
                                <td>{{ file.upload_time }}</td>
                                <td>{{ file.size|format_size }}</td>
                                <td>
                                    <div class="btn-group btn-group-sm">
                                        <a href="{{ url_for('download_file', secure_id=file.secure_id) }}" class="btn btn-outline-primary" title="Download">
                                            <i class="bi bi-download"></i>
                                        </a>
                                        <a href="{{ url_for('file_details', secure_id=file.secure_id) }}" class="btn btn-outline-info" title="View Details">
                                            <i class="bi bi-info-circle"></i>
                                        </a>
                                        <button type="button" class="btn btn-outline-danger" title="Delete" 
                                                data-bs-toggle="modal" data-bs-target="#deleteModal{{ file.secure_id|replace('.', '_') }}">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                    
                                    <!-- Delete Confirmation Modal -->
                                    <div class="modal fade" id="deleteModal{{ file.secure_id|replace('.', '_') }}" tabindex="-1" aria-hidden="true">
                                        <div class="modal-dialog">
                                            <div class="modal-content">
                                                <div class="modal-header bg-danger text-white">
                                                    <h5 class="modal-title">Confirm Delete</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                                </div>
                                                <div class="modal-body">
                                                    Are you sure you want to delete <strong>{{ file.original_name }}</strong>?
                                                    This action cannot be undone.
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <form action="{{ url_for('delete_file', secure_id=file.secure_id) }}" method="post" class="d-inline">
                                                        <button type="submit" class="btn btn-danger">Delete</button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        {% endfor %}
                    {% else %}
                        <tr>
                            <td colspan="5" class="text-center py-4">
                                <i class="bi bi-inbox fs-1 d-block mb-2 text-muted"></i>
                                No files uploaded yet.
                            </td>
                        </tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const overrideCheck = document.getElementById('overridePasswordCheck');
        const overrideField = document.getElementById('overridePasswordField');
        
        overrideCheck.addEventListener('change', function() {
            overrideField.style.display = this.checked ? 'block' : 'none';
        });
    });
</script>
{% endblock %}''')
    
    with open('templates/logs.html', 'w') as f:
        f.write('''{% extends "layout.html" %}

{% block title %}System Logs - Secure File System{% endblock %}

{% block content %}
<div class="card">
    <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="bi bi-journal-text me-2"></i>System Logs</h5>
        <a href="{{ url_for('index') }}" class="btn btn-sm btn-light">Back to Files</a>
    </div>
    <div class="card-body">
        <div class="log-container">{{ logs }}</div>
    </div>
</div>
{% endblock %}''')
    
    with open('templates/file_details.html', 'w') as f:
        f.write('''{% extends "layout.html" %}

{% block title %}File Details - {{ file.original_name }}{% endblock %}

{% block content %}
<div class="card">
    <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="bi bi-file-earmark-text me-2"></i>File Details</h5>
        <a href="{{ url_for('index') }}" class="btn btn-sm btn-light">Back to Files</a>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <div class="mb-3">
                    <label class="fw-bold">Original Filename:</label>
                    <p class="mb-1">{{ file.original_name }}</p>
                </div>
                <div class="mb-3">
                    <label class="fw-bold">File Type:</label>
                    <p class="mb-1">{{ file.file_type }}</p>
                </div>
                <div class="mb-3">
                    <label class="fw-bold">Upload Time:</label>
                    <p class="mb-1">{{ file.upload_time }}</p>
                </div>
            </div>
            <div class="col-md-6">
                <div class="mb-3">
                    <label class="fw-bold">Size:</label>
                    <p class="mb-1">{{ file.size|format_size }}</p>
                </div>
                <div class="mb-3">
                    <label class="fw-bold">Secure ID:</label>
                    <p class="mb-1 text-break">{{ file.secure_id }}</p>
                </div>
                <div class="mb-3">
                    <label class="fw-bold">Current Encryption Key:</label>
                    <div class="input-group">
                        <input type="password" id="currentKey" class="form-control" value="{{ current_password }}" readonly>
                        <span class="input-group-text password-toggle" data-target="currentKey">
                            <i class="bi bi-eye"></i>
                        </span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="d-flex justify-content-between mt-4">
            <a href="{{ url_for('download_file', secure_id=file.secure_id) }}" class="btn btn-primary">
                <i class="bi bi-download me-2"></i>Download File
            </a>
            <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#deleteModal">
                <i class="bi bi-trash me-2"></i>Delete File
            </button>
        </div>
        
        <!-- Delete Confirmation Modal -->
        <div class="modal fade" id="deleteModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-danger text-white">
                        <h5 class="modal-title">Confirm Delete</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        Are you sure you want to delete <strong>{{ file.original_name }}</strong>?
                        This action cannot be undone.
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <form action="{{ url_for('delete_file', secure_id=file.secure_id) }}" method="post" class="d-inline">
                            <button type="submit" class="btn btn-danger">Delete</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}''')
    
    # Start the app
    print("Flask app created successfully!")
    print("Run with: flask run")
    app.run(debug=True)