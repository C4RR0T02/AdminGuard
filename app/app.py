from flask import Flask, render_template, request, redirect, url_for, send_file, abort
from flaskext.markdown import Markdown
from wtforms import BooleanField, StringField, validators
from wtforms.form import BaseForm

if __name__ == '__main__':
    from script.admin_guard import *  # Importation for running app
else:
    from .script.admin_guard import *  # Importation for running test case

import os

# Flask Server
app = Flask(__name__)
Markdown(app)

guide_dictionary = {}
form_data_rule_dictionary = {}

path = os.getcwd()
upload_folder = os.path.join(path, 'app', 'uploads')
if not os.path.isdir(upload_folder):
    os.mkdir(upload_folder)
    print("created upload folder")
download_folder = os.path.join(path, 'app', 'out-files')
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


@app.route('/script-generate', methods=['GET', 'POST'])
def scriptGenerate():
    if request.method == 'POST':
        selected_guide_type = request.form.get('guide_type', default=None)
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            upload_file_path = os.path.join(app.config['upload_folder'],
                                            uploaded_file.filename)
            uploaded_file.save(upload_file_path)
            guide = parseGuide(upload_file_path, selected_guide_type)
            guide_name = uploaded_file.filename.split('.')[0]

            guide_dictionary[guide_name] = dict()
            guide_dictionary[guide_name]["guide_content"] = guide
            guide_dictionary[guide_name]["guide_type"] = selected_guide_type
            return redirect(
                url_for('scriptFieldsGet',
                        guide_name=uploaded_file.filename.split('.')[0]))
    return render_template('script-generate.html')


def enableCheck(enable_id):

    def check(form, field):
        if form[enable_id].data:
            if not field.data:
                raise validators.ValidationError('Field must be filled.')

    return check


def createGuideForm(guide: Guide, formdata=None):
    form_fields = dict()
    for rule in guide.stig_rule_dict.values():
        form_fields[f"{rule.vuln_id}.enable"] = BooleanField("Enable", default=True)
        
        form_fields[f"{rule.vuln_id}.rule_title"] = StringField("rule_title", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.rule_fix_text"] = StringField("rule_fix_text", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.rule_description"] = StringField("rule_description", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.check_content"] = StringField("check_content", [enableCheck(f"{rule.vuln_id}.enable")])


    form = BaseForm(form_fields)
    form.process(formdata)
    return form


@app.route('/script-generate/<guide_name>', methods=['GET'])
def scriptFieldsGet(guide_name):
    guide_details = guide_dictionary.get(guide_name)
    guide = guide_details.get("guide_content")
    if guide is None:
        return "Guide not found", 404
    form = createGuideForm(guide)
    return render_template('script-fields.html',
                           enumerate=enumerate,
                           guide=guide,
                           form=form)

@app.route('/script-generate/<guide_name>', methods=['POST'])
def scriptFieldsPost(guide_name):
    guide_details = guide_dictionary.get(guide_name)
    guide_type = guide_details.get("guide_type")
    guide = guide_details.get("guide_content")
    enable_list = []

    if guide is None or guide_type is None:
        return "Guide not found", 404
    
    fragments = request.form.getlist("items")

    for vuln_id, data in fragments:
        if vuln_id in guide.stig_rule_dict:
            rule = guide.stig_rule_dict[vuln_id]
            rule.rule_title = data["rule_title"]
            rule.rule_fix_text = data["rule_fix_text"]
            rule.rule_description = data["rule_description"]
            rule.check_content = data["check_content"]
            if data["enable"]:
                enable_list.append(rule.vuln_id)
                rule.check_commands = rule._getRequiredFields(guide_type, rule.check_content)
                rule.fix_commands = rule._getRequiredFields(guide_type, rule.fix_commands)

    if guide_details.get("guide_type") == "Windows":
        windowsCreateScript(guide, enable_list)
    elif guide_details.get("guide_type") == "Linux":
        linuxCreateScript(guide, enable_list)

    return redirect(url_for('scriptDownload', guide_name=guide_name))

@app.route('/script-generate/<guide_name>/download', methods=['GET'])
def scriptDownload(guide_name):
    if request.method == 'GET':
        downloadCheckScript = url_for('downloadScript',
                                      guide_name=guide_name,
                                      file='checkscript')
        downloadFixScript = url_for('downloadScript',
                                    guide_name=guide_name,
                                    file='fixscript')
        downloadManualCheck = url_for('downloadScript',
                                      guide_name=guide_name,
                                      file='manualcheck')
        downloadManualFix = url_for('downloadScript',
                                    guide_name=guide_name,
                                    file='manualfix')
        return render_template('script-download.html',
                               guide_name=guide_name,
                               downloadFixScript=downloadFixScript,
                               downloadCheckScript=downloadCheckScript,
                               downloadManualCheck=downloadManualCheck,
                               downloadManualFix=downloadManualFix)
    return render_template('script-download.html')


@app.route('/script-generate/<guide_name>/download/<file>', methods=['GET'])
def downloadScript(guide_name, file):
    guide_details = guide_dictionary.get(guide_name)
    guide_type = guide_details["guide_type"]

    if guide_type == "Linux":
        file_extension = ".sh"
    elif guide_type == "Windows":
        file_extension = ".ps1"
    else:
        file_extension = ""

    if file != 'checkscript' and file != 'fixscript' and file != 'manualcheck' and file != 'manualfix':
        return "File not found", 404

    if file == 'checkscript':
        checkscript = os.path.join(download_folder, guide_name, guide_name + '-CheckScript' + file_extension)
        if not os.path.isfile(checkscript):
            abort(404)
        return send_file(checkscript, as_attachment=True)
    if file == 'fixscript':
        fixscript = os.path.join(download_folder, guide_name, guide_name + '-FixScript' + file_extension)
        if not os.path.isfile(fixscript):
            abort(404)
        return send_file(fixscript, as_attachment=True), 200
    if file == 'manualcheck':
        manualcheck = os.path.join(download_folder, guide_name, guide_name + '-ManualCheck.txt')
        if not os.path.isfile(manualcheck):
            abort(404)
        return send_file(manualcheck, as_attachment=True)
    if file == 'manualfix':
        manualfix = os.path.join(download_folder, guide_name, guide_name + '-ManualFix.txt')
        if not os.path.isfile(manualfix):
            abort(404)
        return send_file(manualfix, as_attachment=True)


@app.route('/template-generate', methods=['GET'])
def templateGenerate():
    return render_template('template-generate.html')


@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400  # Bad Request


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404,  # Page Not Found


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500  # Internal Server Error


# main driver function
if __name__ == '__main__':
    app.run(debug=True)
