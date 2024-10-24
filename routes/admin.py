import os
from flask import render_template, request, redirect, flash
from werkzeug.utils import secure_filename
from . import app
from csv_prediction import allowed_file, convert_pcap_to_csv, predict_csv

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/blockchain_explorer')
def blockchain_explorer():
    return render_template('blockchain_explorer.html')

@app.route('/detection')
def detection():
    return render_template('detection.html')

@app.route('/filter_search')
def filter_search():
    return render_template('filter_search.html')

@app.route('/history_analysis')
def history_analysis():
    return render_template('history_analysis.html')

@app.route('/csv_prediction', methods=['GET', 'POST'])
def csv_prediction():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            if filename.endswith('.pcap'):
                csv_path = convert_pcap_to_csv(file_path)
            else:
                csv_path = file_path

            results = predict_csv(csv_path)

            return render_template('csv_prediction.html', results=results)


    return render_template('csv_prediction.html', results=None)
