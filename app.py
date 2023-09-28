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
            return redirect(url_for('scriptFields', guide_name=uploaded_file.filename))
    return render_template('script-generate.html')

@app.route('/script-generate/<guide_name>', methods=['GET', 'POST'])
def scriptFields(guide_name):
    if request.method == 'GET':
        guide = guide_dictionary[guide_name]
        rule_list = []
        for rule in guide.stig_rule_dict.values():
            temp_rule_dict = {}
            temp_rule_dict["rule_name"] = rule.rule_name
            temp_rule_dict["rule_title"] = rule.rule_title
            temp_rule_dict["vuln_id"] = rule.vuln_id
            temp_rule_dict["rule_id"] = rule.rule_id
            temp_rule_dict["stig_id"] = rule.stig_id
            temp_rule_dict["rule_fix_text"] = rule.rule_fix_text
            temp_rule_dict["rule_description"] = rule.rule_description
            temp_rule_dict["check_content"] = rule.check_content
            temp_rule_dict["category_score"] = rule.category_score
            temp_rule_dict["check_commands"] = rule.check_commands
            temp_rule_dict["fix_commands"] = rule.fix_commands
            rule_list.append(temp_rule_dict)
        return render_template('script-fields.html', StigContentList=rule_list)
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



