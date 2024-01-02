from flask import Flask, render_template, request, redirect, url_for, send_file, abort
from wtforms import BooleanField, StringField, validators
from wtforms.form import BaseForm

if __name__ == '__main__':
    # Importation for running app
    from script.stig_script_gen import *
    from script.template_gen import *
    from script.nessusaudit import *
else:
    # Importation for running test case
    from .script.stig_script_gen import *
    from .script.template_gen import *
    from .script.nessusaudit import *

import os

# Flask Server
app = Flask(__name__)

guide_dictionary = {}
template_dictionary = {}
form_data_rule_dictionary = {}

path = os.getcwd()

# Create upload and download folders if they don't exist
upload_folder = os.path.join(path, 'app', 'uploads')
if not os.path.isdir(os.path.join(upload_folder, 'stig')):
    os.mkdirs(os.path.join(upload_folder, 'stig'))
if not os.path.isdir(os.path.join(upload_folder, 'vatemplate')):
    os.mkdirs(os.path.join(upload_folder, 'vatemplate'))

download_folder = os.path.join(path, 'app', 'out-files')
if not os.path.isdir(download_folder):
    os.mkdirs(download_folder)

# Set app config
app.config['upload_folder'] = upload_folder
app.config['download_folder'] = download_folder
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.xml', '.audit']


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# Script Generation


@app.route('/script-generate', methods=['GET', 'POST'])
def scriptGenerate():
    if request.method == 'POST':
        # Get the guide type and uploaded file
        selected_guide_type = request.form.get('guide_type', default=None)
        uploaded_file = request.files['file']
        # Check if the file is valid and upload it to the server
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            upload_file_path = os.path.join(app.config['upload_folder'],
                                            "stig", uploaded_file.filename)
            uploaded_file.save(upload_file_path)
            # Parse the guide
            guide = parseGuide(upload_file_path, selected_guide_type)
            guide_name = uploaded_file.filename.split('.')[0]
            # Add the guide to the dictionary with the guide name as the key
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
        # Create fields for the various rule attributes
        form_fields[f"{rule.vuln_id}.enable"] = BooleanField("Enable",
                                                             default=True)
        form_fields[f"{rule.vuln_id}.rule_title"] = StringField(
            "rule_title", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.rule_fix_text"] = StringField(
            "rule_fix_text", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.rule_description"] = StringField(
            "rule_description", [enableCheck(f"{rule.vuln_id}.enable")])
        form_fields[f"{rule.vuln_id}.check_content"] = StringField(
            "check_content", [enableCheck(f"{rule.vuln_id}.enable")])

    form = BaseForm(form_fields)
    form.process(formdata)
    return form


@app.route('/script-generate/<guide_name>', methods=['GET'])
def scriptFieldsGet(guide_name: str):
    # Get the guide information from the dictionary
    guide_details = guide_dictionary.get(guide_name)
    guide = guide_details.get("guide_content")
    if guide is None:
        return "Guide not found", 404
    # Create a form for the guide
    form = createGuideForm(guide)
    return render_template('script-fields.html',
                           enumerate=enumerate,
                           guide=guide,
                           form=form)


@app.route('/script-generate/<guide_name>', methods=['POST'])
def scriptFieldsPost(guide_name: str):
    # Get the guide information from the dictionary
    guide_details = guide_dictionary.get(guide_name)
    guide_type = guide_details.get("guide_type")
    guide = guide_details.get("guide_content")
    # Initialize a list to store the enabled vuln_ids
    enable_list = []

    if guide is None or guide_type is None:
        return "Guide not found", 404

    fragments = dict(request.form)

    for data in fragments.items():
        # Check if the vuln_id is enabled and add it to the list
        if data[0].endswith(".enable") and data[1] == 'y':
            vuln_id = data[0].split(".")[0]
            enable_list.append(vuln_id)
        # Update the rule attributes
        if data[0].endswith(".rule_title"):
            vuln_id = data[0].split(".")[0]
            rule = guide.stig_rule_dict[vuln_id]
            rule.rule_title = data[1]
        if data[0].endswith(".rule_description"):
            vuln_id = data[0].split(".")[0]
            rule = guide.stig_rule_dict[vuln_id]
            rule.rule_description = data[1]
        if data[0].endswith(".rule_fix_text"):
            vuln_id = data[0].split(".")[0]
            rule = guide.stig_rule_dict[vuln_id]
            rule.rule_fix_text = data[1]
            rule.fix_commands = rule._getRequiredFields(
                guide_type, rule.rule_fix_text)
        if data[0].endswith(".check_content"):
            vuln_id = data[0].split(".")[0]
            rule = guide.stig_rule_dict[vuln_id]
            rule.check_content = data[1]
            rule.check_commands = rule._getRequiredFields(
                guide_type, rule.check_content)

    # Create the script files based on the guide type and enabled vuln_ids
    if guide_details.get("guide_type") == "Windows":
        windowsCreateScript(guide, enable_list)
    elif guide_details.get("guide_type") == "Linux":
        linuxCreateScript(guide, enable_list)

    # Generate the XML and zip files
    generateXml(guide)
    generateZip(guide)

    return redirect(url_for('scriptDownload', guide_name=guide_name))


@app.route('/script-generate/<guide_name>/download', methods=['GET'])
def scriptDownload(guide_name: str):
    if request.method == 'GET':
        # define the download links
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
        downloadNewGuide = url_for('downloadScript',
                                   guide_name=guide_name,
                                   file='newguide')
        downloadZipped = url_for('downloadScript',
                                 guide_name=guide_name,
                                 file='zipped')
        return render_template(
            'script-download.html',
            guide_name=guide_name,
            downloadFixScript=downloadFixScript,
            downloadCheckScript=downloadCheckScript,
            downloadManualCheck=downloadManualCheck,
            downloadManualFix=downloadManualFix,
            downloadNewGuide=downloadNewGuide,
            downloadZipped=downloadZipped,
        )
    return render_template('script-download.html')


@app.route('/script-generate/<guide_name>/download/<file>', methods=['GET'])
def downloadScript(guide_name: str, file: str):
    # Get the guide information from the dictionary
    guide_details = guide_dictionary.get(guide_name)
    guide_type = guide_details["guide_type"]

    # Set the file extension based on the guide type
    if guide_type == "Linux":
        file_extension = ".sh"
    elif guide_type == "Windows":
        file_extension = ".ps1"
    else:
        file_extension = ""

    # Send file based on file requested or return a 404 error when no file found
    if file == 'checkscript':
        checkscript = os.path.join(
            download_folder, guide_name,
            guide_name + '-CheckScript' + file_extension)
        if not os.path.isfile(checkscript):
            abort(404)
        return send_file(checkscript, as_attachment=True)
    if file == 'fixscript':
        fixscript = os.path.join(download_folder, guide_name,
                                 guide_name + '-FixScript' + file_extension)
        if not os.path.isfile(fixscript):
            abort(404)
        return send_file(fixscript, as_attachment=True), 200
    if file == 'manualcheck':
        manualcheck = os.path.join(download_folder, guide_name,
                                   guide_name + '-ManualCheck.txt')
        if not os.path.isfile(manualcheck):
            abort(404)
        return send_file(manualcheck, as_attachment=True)
    if file == 'manualfix':
        manualfix = os.path.join(download_folder, guide_name,
                                 guide_name + '-ManualFix.txt')
        if not os.path.isfile(manualfix):
            abort(404)
        return send_file(manualfix, as_attachment=True)
    if file == 'newguide':
        newguide = os.path.join(download_folder, guide_name,
                                'updated-' + guide_name + '.xml')
        if not os.path.isfile(newguide):
            abort(404)
        return send_file(newguide, as_attachment=True)
    if file == 'zipped':
        zipped = os.path.join(download_folder, guide_name, guide_name + '.zip')
        if not os.path.isfile(zipped):
            abort(404)
        return send_file(zipped, as_attachment=True)

    abort(404)


# Template Generation


@app.route('/template-generate', methods=['GET', 'POST'])
def templateGenerate():
    if request.method == 'POST':
        # Get the template type and uploaded file
        selected_template_type = request.form.get('template_type',
                                                  default=None)
        uploaded_file = request.files['file']
        # Check if the file is valid and upload it to the server
        if uploaded_file.filename != '':
            file_ext = os.path.splitext(uploaded_file.filename)[1]
            if file_ext not in app.config['UPLOAD_EXTENSIONS']:
                abort(400)
            upload_file_path = os.path.join(app.config['upload_folder'],
                                            "vatemplate",
                                            uploaded_file.filename)
            uploaded_file.save(upload_file_path)
            # Parse the template
            template = parseTemplate(upload_file_path, selected_template_type)
            template_name = uploaded_file.filename.split('.')[0]
            # Add the template to the dictionary with the template name as the key
            template_dictionary[template_name] = dict()
            template_dictionary[template_name]["template_content"] = template
            template_dictionary[template_name][
                "template_type"] = selected_template_type
            return redirect(
                url_for('templateFieldsGet',
                        template_name=uploaded_file.filename.split('.')[0]))
    return render_template('template-generate.html')


def createTemplateForm(template: Template, formdata=None):
    form_fields = dict()
    for vuln_id in template.template_rule_dict[0].keys():
        rule = template.template_rule_dict[0][vuln_id]
        list_of_keys = list(rule.dictionary_fields.dictionary_fields.keys())
        # Create fields for the various rule attributes
        form_fields[f"{rule.vuln_id}.enable"] = BooleanField("Enable",
                                                             default=True)
        for key in list_of_keys:
            form_fields[f"{vuln_id}.{key}"] = StringField(
                f"{vuln_id}.{key}", [enableCheck(f"{vuln_id}.enable")])

    form = BaseForm(form_fields)
    form.process(formdata)
    return form


@app.route('/template-generate/<template_name>', methods=['GET'])
def templateFieldsGet(template_name: str):
    # Get the template information from the dictionary
    template_details = template_dictionary.get(template_name)
    template = template_details.get("template_content")
    if template is None:
        return "Template not found", 404
    # Create a form for the template
    form = createTemplateForm(template)
    return render_template('template-fields.html',
                           enumerate=enumerate,
                           template=template,
                           form=form)


@app.route('/template-generate/<template_name>', methods=['POST'])
def templateFieldsPost(template_name: str):
    # Get the template information from the dictionary
    template_details = template_dictionary.get(template_name)
    template_type = template_details.get("template_type")
    template = template_details.get("template_content")
    # Initialize a list to store the enabled vuln_ids
    enable_list = []

    if template is None or template_type is None:
        return "Template not found", 404

    fragments = dict(request.form)

    for key, value in fragments.items():
        vuln_id, field_name = key.split(".", 1)
        # Check if the vuln_id is enabled and add it to the list
        if field_name == "enable" and value == 'y':
            enable_list.append(vuln_id)
        # Update the rule attributes
        else:
            if vuln_id in template.template_rule_dict[0].keys():
                rule = template.template_rule_dict[0][vuln_id]
                rule.dictionary_fields.dictionary_fields[field_name] = value

    # Generate the template file
    gen_template(template)

    return redirect(url_for('templateDownload', template_name=template_name))


@app.route('/template-generate/<template_name>/download', methods=['GET'])
def templateDownload(template_name: str):
    if request.method == 'GET':
        # define the download links
        downloadTemplate = url_for('downloadTemplate',
                                   template_name=template_name,
                                   file='template')
        return render_template(
            'template-download.html',
            template_name=template_name,
            downloadTemplate=downloadTemplate,
        )
    return render_template('template-download.html')


@app.route('/template-generate/<template_name>/download/<file>',
           methods=['GET'])
def downloadTemplate(template_name: str, file: str):
    # Send file based on file requested or return a 404 error when no file found
    if file == 'template':
        template = os.path.join(download_folder, template_name,
                                template_name + '-updated.audit')
        if not os.path.isfile(template):
            abort(404)
        return send_file(template, as_attachment=True)

    abort(404)


# Error handlers
@app.errorhandler(400)
def bad_request(e):
    return render_template('errors/400.html'), 400  # Bad Request


@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404,  # Page Not Found


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500  # Internal Server Error


# main driver function
if __name__ == '__main__':
    app.run(debug=True)
