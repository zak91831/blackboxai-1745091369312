from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import os
import io
import json
import csv
import tempfile
from werkzeug.utils import secure_filename
import pdfrecon  # Import the existing scanning functions

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key in production

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'pdf_file' not in request.files and not request.form.get('pdf_url'):
        flash('No file or URL provided')
        return redirect(url_for('index'))

    results = []
    if 'pdf_file' in request.files:
        file = request.files['pdf_file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            results = pdfrecon.scan_pdf(filepath)
            os.remove(filepath)
        else:
            flash('Invalid file type. Only PDF files are allowed.')
            return redirect(url_for('index'))
    elif request.form.get('pdf_url'):
        url = request.form.get('pdf_url')
        pdf_path = pdfrecon.download_pdf(url)
        if not pdf_path:
            flash('Failed to download PDF from URL.')
            return redirect(url_for('index'))
        results = pdfrecon.scan_pdf(pdf_path)
        os.unlink(pdf_path)

    # Store results in session or temporary storage for download
    request.environ['scan_results'] = results
    return render_template('results.html', results=results)

@app.route('/download/<format>')
def download(format):
    results = request.environ.get('scan_results')
    if not results:
        flash('No scan results available for download.')
        return redirect(url_for('index'))

    if format == 'json':
        output = io.StringIO()
        json.dump(results, output, indent=2)
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype='application/json', as_attachment=True, download_name='scan_results.json')
    elif format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["file", "url_or_token", "type", "confidence", "severity"])
        for res in results:
            for link in res.get("suspicious_links", []):
                writer.writerow([
                    res.get("file"),
                    link.get("url") or link.get("match"),
                    link.get("type"),
                    link.get("confidence"),
                    link.get("severity", "")
                ])
            for token in res.get("tokens", []):
                writer.writerow([res.get("file"), token, "token", "", ""])
        output.seek(0)
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='scan_results.csv')
    else:
        flash('Unsupported download format requested.')
        return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
