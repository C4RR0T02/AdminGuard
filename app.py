from flask import Flask, render_template, request, redirect, url_for

# Flask Server
app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/script-generate', methods=['GET'])
def scriptGenerate():
    return render_template('script-generate.html')

@app.route('/template-generate', methods=['GET'])
def templateGenerate():
    return render_template('template-generate.html')


# main driver function
if __name__ == '__main__':
   
    app.run()
