from flask import Flask, render_template, request, redirect, url_for
from script.Linux_AdminGuard import *
import os

# Flask Server
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.xml']

guide_dictionary = {}

path = os.getcwd()
upload_folder = os.path.join(path, 'uploads')
if not os.path.isdir(upload_folder):
    os.mkdir(upload_folder)
app.config['upload_folder'] = upload_folder

@app.route('/', methods=['GET'])
def index():
    print("Index page")
    return render_template('index.html')

@app.route('/script-generate', methods=['GET','POST'])
def scriptGenerate():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                return "Invalid file type - XML files only", 400
            upload_file_path = os.path.join(app.config['upload_folder'], uploaded_file.filename)
            uploaded_file.save(upload_file_path)
            guide = parseGuide(upload_file_path)
            guide_dictionary[uploaded_file.filename] = guide
            print(guide_dictionary)
            return redirect(url_for('scriptFields', guide_name=uploaded_file.filename))
    return render_template('script-generate.html')

@app.route('/script-generate/<guide_name>', methods=['GET', 'POST'])
def scriptFields(guide_name):
    if request.method == 'GET':
        print("Guide Name: " + guide_name)
        guide = guide_dictionary[guide_name]
        rule_header_list = ["Vulnerability ID", "Rule ID", "Severity"]
        rule_list = []
        for rule in guide.stig_rule_dict.values():
            temp_rule_dict = {}
            temp_rule_dict["Vulnerability ID"] = rule.vuln_id
            temp_rule_dict["Rule ID"] = rule.rule_id
            temp_rule_dict["Severity"] = rule.rule_severity
            rule_list.append(temp_rule_dict)
        return render_template('script-fields.html', rule_header_list=rule_header_list, rule_list=rule_list)
    # guide.check_commands
    # guide.fix_commands
    if request.method == 'POST':
        return redirect(url_for('scriptDownload', guide_name=guide_name))
    return render_template("script-fields.html")

# @app.route('/script-generate/<guide_name>/download', methods=['GET'])
# def scriptDownload(guide_name):
#     return render_template('script-download.html')

@app.route('/template-generate', methods=['GET'])
def templateGenerate():
    return render_template('template-generate.html')



# main driver function
if __name__ == '__main__':
    app.run(debug=True)


# References:
# https://code-maven.com/slides/python/flask-internal-redirect-parameters
# https://www.geeksforgeeks.org/redirecting-to-url-in-flask/
# https://www.codingninjas.com/studio/library/file-uploading-in-flask
# https://www.geeksforgeeks.org/how-to-upload-file-in-python-flask/
