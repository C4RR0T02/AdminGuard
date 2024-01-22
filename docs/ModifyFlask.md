# Modifying Flask Application

The Flask Application is the central component of our system, serving as the backbone for handling various functionalities and providing a user-friendly interface for users. 

## *`Application Configurations`*

The application configuration for the flask applications help to set the various folders as well as any settings that affects the security of the application. Below are the configurations that has been set up

```py
# Defining Variables
upload_folder = os.path.join(path, 'app', 'uploads')
download_folder = os.path.join(path, 'app', 'out-files')

# Application Configuration
app.config['upload_folder'] = upload_folder
app.config['download_folder'] = download_folder
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.xml', '.audit']
```

The configurations above helps to control the default folders where files are uploaded to, set the maximum content length a file is read from the incoming request data before being dropped by the server as well as the setting of the upload extensions to only accept files with extensions which are configured. 

## *`Error Pages`*

The error pages are configured to take in the default errors such as the Not Found Error, Internal Server Error as well as the Bad Request error. These errors will redirect users towards the error page and throw a generic error towards the users. The HTML page of the error pages are stated below

|Error Page|Status Code|File Path|
|:--|:--:|:--:|
|Bad Request|400|/app/templates/errors/400.html|
|Not Found|404|/app/templates/errors/404.html|
|Internal Server Error|500|/app/templates/errors/500.html|

To add an error page route, the following code straucture can be followed

```py
@app.errorhandler(<error_code>)
def bad_request(e):
    return render_template('<file_path>'), <error_code>
```

## *`Functions of Application`*

The following section outlines the various functions within the Flask Application. 

### *`Common Functions and Routes`*

#### @app.route('/', methods=['GET'])

This route is the route to display the index page of the application.

#### enableCheck(enable_id)

This function is to check if the form field is required to be filled up based on the enabling of rule for the specific VulnID.

### *`STIG Script Generation Front-End Functions`*

#### @app.route('/script-generate', methods=['GET'])

This route is the route to display the STIG file upload page of the application from the `app/templates/script-generate.html` page. 

#### @app.route('/script-generate', methods=['POST'])

This route is to POST the file and user script type selection back to the server to be stored and used.

#### createGuideForm(guide: Guide, formdata=None)

This route is to generate the form with the various VulnID and rule fields as the ID and the content as the value. 

#### @app.route('/script-generate/<guide_name>', methods=['GET'])

This route is to render the various rules found within the guide in the form using the `createGuideForm` function on the `app/templates/script-fields.html` page.

#### @app.route('/script-generate/<guide_name>', methods=['POST'])

This route is for the application to make a POST request in fragments by the VulnID to update the data with the new user inputs and the generation of the various files. 

#### @app.route('/script-generate/<guide_name>/download', methods=['GET'])

This route is for users to access to download all created script files.

#### @app.route('/script-generate/<guide_name>/download/<file>', methods=['GET'])

This route is to retrieve the files created and to send the files to the front-end based on the type of file requested.

### *`Template File Generation Front-End Functions`*

#### @app.route('/template-generate', methods=['GET'])

This route is the route to display the Template file upload page of the application from the `app/templates/template-generate.html` page. 

#### @app.route('/template-generate', methods=['POST'])

This route is to POST the file and user template selection back to the server to be stored and used.

#### createTemplateForm(template: Template, formdata=None)

This route is to generate the form with the various VulnID and rule fields as the ID and the content as the value. 

#### @app.route('/template-generate/<template_name>', methods=['GET'])

This route is to render the various rules found within the template in the form using the `createTemplateForm` function on the `app/templates/template-fields.html` page.

#### @app.route('/template-generate/<template_name>', methods=['POST'])

This route is for the application to make a POST request to update the data with the new user inputs and the generation of the new template file. 

#### @app.route('/template-generate/<template_name>/download', methods=['GET'])

This route is for users to access to download all created template files.

#### @app.route('/template-generate/<template_name>/download/<file>', methods=['GET'])

This route is to retrieve the files created and to send the files to the front-end based on the type of file requested.
