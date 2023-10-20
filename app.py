from flask import Flask, render_template, request, redirect, url_for, send_file
from flaskext.markdown import Markdown
from script.Linux_AdminGuard import *
import os

# Flask Server
app = Flask(__name__)
Markdown(app)

guide_dictionary = {}
form_data_rule_dictionary = {}

path = os.getcwd()
upload_folder = os.path.join(path, 'uploads')
if not os.path.isdir(upload_folder):
    os.mkdir(upload_folder)
    print("created upload folder")
download_folder = os.path.join(path, 'out-files')
if not os.path.isdir(download_folder):
    os.mkdir(download_folder)
    print("created download folder")

app.config['upload_folder'] = upload_folder
app.config['download_folder'] = download_folder
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.xml']

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/script-generate', methods=['GET','POST'])
def scriptGenerate():
    if request.method == 'POST':
        selected_guide_type = request.form.get('guide_type', default=None)
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                return "Invalid file type - XML files only", 400
            upload_file_path = os.path.join(app.config['upload_folder'], uploaded_file.filename)
            uploaded_file.save(upload_file_path)
            guide = parseGuide(upload_file_path)
            guide_dictionary[uploaded_file.filename.split('.')[0]] = guide
            guide_dictionary["guide_type"] = selected_guide_type
            return redirect(url_for('scriptFields', guide_name=uploaded_file.filename.split('.')[0]))
    return render_template('script-generate.html')

@app.route('/script-generate/<guide_name>', methods=['GET', 'POST'])
def scriptFields(guide_name):
    guide = guide_dictionary.get(guide_name)
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
    if request.method == 'GET':
        return render_template('script-fields.html', StigContentList=rule_list)
    if request.method == 'POST':
        form_data = request.form
        form_data_dict = dict(form_data)
        form_data_rule_list = []
        rule_vuln_id_list = []
        for rule_data in form_data_dict.keys():
            rule_data_field = rule_data.split('-')
            if len(rule_data_field) <= 3:
                if form_data_dict[rule_data] == 'on':
                    rule_vuln_id_list.append(rule_data_field[0] + "-" + rule_data_field[1])
            if len(rule_data_field) > 3:
                rule_vuln_id = rule_data_field[0] + "-" + rule_data_field[1]
                rule_field_for_input = rule_data_field[2]
                rule_command = rule_data_field[3:-1]
                rule_action = rule_data_field[-1]
                rule_user_input = form_data_dict[rule_data]
                full_command = ""
                for i, split_text in enumerate(rule_command):
                    full_command += split_text
                    if i < len(rule_command) - 1:
                        full_command += "-"
                if rule_vuln_id in rule_vuln_id_list:
                    form_data_rule_list.append([rule_vuln_id, rule_field_for_input, full_command, rule_action, rule_user_input])
        for rule in form_data_rule_list:
            vuln_id = rule[0]
            field_for_input = rule[1]
            command = rule[2]
            action = rule[3]
            user_input = rule[4]
            if vuln_id in form_data_rule_dictionary.keys():
                if action in form_data_rule_dictionary[vuln_id].keys():
                    replacements = form_data_rule_dictionary[vuln_id][action]
                    for command_dictionary in replacements:
                        if command in command_dictionary.keys():
                            continue    
                        else:
                            replacements.append({command: {field_for_input: user_input}})
                            form_data_rule_dictionary[vuln_id][action] = replacements
                else:
                    form_data_rule_dictionary[vuln_id][action] = [{command: {field_for_input: user_input}}]
            else:
                form_data_rule_dictionary[vuln_id] = {action: [{command: {field_for_input: user_input}}]}
        return redirect(url_for('scriptDownload', guide_name=guide_name))
    return render_template("script-fields.html")

@app.route('/script-generate/<guide_name>/download', methods=['GET', 'POST'])
def scriptDownload(guide_name):
    guide = guide_dictionary.get(guide_name)
    user_input = form_data_rule_dictionary
    if request.method == 'GET':
        createScript(guide, user_input)
        downloadCheckScript = url_for('downloadScript', guide_name=guide_name, file='checkscript')
        downloadFixScript = url_for('downloadScript', guide_name=guide_name, file='fixscript')
        return render_template('script-download.html', guide_name=guide_name, downloadFixScript = downloadFixScript, downloadCheckScript = downloadCheckScript)
    return render_template('script-download.html')

@app.route('/script-generate/<guide_name>/download/<file>', methods=['GET'])
def downloadScript(guide_name, file):
    if file == 'checkscript':
        checkscript = os.path.join(download_folder, guide_name + '-CheckScript.sh')
        print(checkscript)
        return send_file(checkscript, as_attachment=True)
    if file == 'fixscript':
        fixscript = os.path.join(download_folder, guide_name + '-FixScript.sh')
        return send_file(fixscript, as_attachment=True)

@app.route('/template-generate', methods=['GET'])
def templateGenerate():
    return render_template('template-generate.html')

# @app.errorhandler(404)
# def page_not_found(e):
#     return render_template('404.html'), 404,  # Page Not Found

# @app.errorhandler(500)
# def internal_server_error(e):
#     return render_template('500.html'), 500  # Internal Server Error

# main driver function
if __name__ == '__main__':
    app.run(debug=True)



