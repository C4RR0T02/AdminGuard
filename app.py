from flask import Flask, render_template, request, redirect, url_for

# Flask Server
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/generate', methods=['GET'])
def test():
    return render_template('generate.html')


# main driver function
if __name__ == '__main__':
   
    app.run()
