from routes import app

if __name__ == '__main__':
    UPLOAD_FOLDER = 'uploads'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.run(debug=True,port=8080)