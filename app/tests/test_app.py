import os
import pytest
import shutil
from io import BytesIO
from ..app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client


def test_get_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Strengthening OS Security from Within' in response.data


def test_get_script_generate_page(client):
    response = client.get('/script-generate')
    assert response.status_code == 200
    assert b'Upload STIG File' in response.data


def test_post_script_generate_page_linux(client):
    shutil.copyfile(
        'app/tests/testFiles/test_linux_1.xml',
        os.path.join(app.config['upload_folder'], 'test_linux_1.xml'))
    with open('app/tests/testFiles/test_linux_1.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_linux_1.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.get(new_url)
        assert response.status_code == 200
        assert b'<h1 class="text-center mb-5">Customize STIG Rules</h1>' in response.data


def test_post_script_generate_page_windows(client):
    shutil.copyfile(
        'app/tests/testFiles/test_windows_1.xml',
        os.path.join(app.config['upload_folder'], 'test_windows_1.xml'))
    with open('app/tests/testFiles/test_windows_1.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_windows_1.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.get(new_url)
        assert response.status_code == 200
        assert b'<h1 class="text-center mb-5">Customize STIG Rules</h1>' in response.data


def test_post_script_generate_page_invalid(client):
    shutil.copyfile('app/tests/testFiles/test.yaml',
                    os.path.join(app.config['upload_folder'], 'test.yaml'))
    with open('app/tests/testFiles/test.yaml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test.yaml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    assert response.status_code == 400


def test_script_fields_get_linux(client):
    shutil.copyfile(
        'app/tests/testFiles/test_linux_2.xml',
        os.path.join(app.config['upload_folder'], 'test_linux_2.xml'))
    with open('app/tests/testFiles/test_linux_2.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_linux_2.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.get(new_url)
        assert b'<input class="form-control" id="V-230222.rule_title" name="V-230222.rule_title" type="text" value="RHEL 8 vendor packaged system security patches and updates must be installed and up to date.">\n' in response.data


def test_script_fields_get_windows(client):
    shutil.copyfile(
        'app/tests/testFiles/test_windows_2.xml',
        os.path.join(app.config['upload_folder'], 'test_windows_2.xml'))
    with open('app/tests/testFiles/test_windows_2.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_windows_2.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Windows',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.get(new_url)
        assert b'''<textarea class="auto-expand form-control" id="V-254239.rule_description" name="V-254239.rule_description" rows="6">The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password. The built-in Administrator account is not generally used and its password may not be changed as frequently as necessary. Changing the password for the built-in Administrator account on a regular basis will limit its exposure.

Windows LAPS must be used  to change the built-in Administrator account password.</textarea>\n''' in response.data


def test_script_fields_post_linux(client):
    shutil.copyfile(
        'app/tests/testFiles/test_linux_2.xml',
        os.path.join(app.config['upload_folder'], 'test_linux_2.xml'))
    with open('app/tests/testFiles/test_linux_2.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_linux_2.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.post(new_url)
        if response.status_code == 302:
            new_url = response.headers['Location']
            response = client.get(new_url)
            assert response.status_code == 200


# def test_script_fields_post_windows(client):
#     shutil.copyfile('app/tests/testFiles/test_windows_2.xml',
#         os.path.join(app.config['upload_folder'], 'test_windows_2.xml'))
#     with open('app/tests/testFiles/test_windows_2.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_windows_2.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Windows',
#                                'file': uploaded_file
#                            })
#     print(response)
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             assert response.status_code == 200


# def test_script_download_get_page_linux(client):
#     shutil.copyfile(
#         'app/tests/testFiles/test_linux_2.xml',
#         os.path.join(app.config['upload_folder'], 'test_linux_2.xml'))
#     with open('app/tests/testFiles/test_linux_2.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_linux_2.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Linux',
#                                'file': uploaded_file
#                            })
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             assert response.status_code == 200
#             assert b'<h1 class="text-center my-5 mx-auto">Download Scripts for test_linux_2</h1>\n' in response.data


# def test_script_download_get_page_windows(client):
#     shutil.copyfile(
#         'app/tests/testFiles/test_windows_2.xml',
#         os.path.join(app.config['upload_folder'], 'test_windows_2.xml'))
#     with open('app/tests/testFiles/test_windows_2.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_windows_2.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Windows',
#                                'file': uploaded_file
#                            })
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             assert response.status_code == 200
#             assert b'<h1 class="text-center my-5 mx-auto">Download Scripts for test_windows_2</h1>\n' in response.data


# def test_download_file_linux(client):
#     shutil.copyfile(
#         'app/tests/testFiles/test_linux_2.xml',
#         os.path.join(app.config['upload_folder'], 'test_linux_2.xml'))
#     with open('app/tests/testFiles/test_linux_2.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_linux_2.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Linux',
#                                'file': uploaded_file
#                            })
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             if response.status_code == 200:
#                 check_script_url = '/script-generate/test_linux_2/download/checkscript'
#                 response = client.get(check_script_url)
#                 assert response.status_code == 200
#                 fix_script_url = '/script-generate/test_linux_2/download/fixscript'
#                 response = client.get(fix_script_url)
#                 assert response.status_code == 200


# def test_download_file_windows(client):
#     shutil.copyfile(
#         'app/tests/testFiles/test_windows_2.xml',
#         os.path.join(app.config['upload_folder'], 'test_windows_2.xml'))
#     with open('app/tests/testFiles/test_windows_2.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_windows_2.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Windows',
#                                'file': uploaded_file
#                            })
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             if response.status_code == 200:
#                 check_script_url = '/script-generate/test_windows_2/download/checkscript'
#                 response = client.get(check_script_url)
#                 assert response.status_code == 200
#                 fix_script_url = '/script-generate/test_windows_2/download/fixscript'
#                 response = client.get(fix_script_url)
#                 assert response.status_code == 200


# def test_download_invalid_file(client):
#     shutil.copyfile(
#         'app/tests/testFiles/test_linux_4.xml',
#         os.path.join(app.config['upload_folder'], 'test_linux_4.xml'))
#     with open('app/tests/testFiles/test_linux_4.xml', 'rb') as file:
#         uploaded_file = (BytesIO(file.read()), 'test_linux_4.xml')
#     response = client.post('/script-generate',
#                            data={
#                                'guide_type': 'Linux',
#                                'file': uploaded_file
#                            })
#     if response.status_code == 302:
#         new_url = response.headers['Location']
#         response = client.post(new_url)
#         if response.status_code == 302:
#             new_url = response.headers['Location']
#             response = client.get(new_url)
#             if response.status_code == 200:
#                 os.remove(
#                     os.path.join(app.config['download_folder'],
#                                  'test_linux_4-CheckScript.sh'))
#                 os.remove(
#                     os.path.join(app.config['download_folder'],
#                                  'test_linux_4-FixScript.sh'))
#                 check_script_url = '/script-generate/test_linux_4/download/checkscript'
#                 response = client.get(check_script_url)
#                 assert response.status_code == 404
#                 fix_script_url = '/script-generate/test_linux_4/download/fixscript'
#                 response = client.get(fix_script_url)
#                 assert response.status_code == 404


# def test_remove_files():
#     folder_path = os.path.join(os.getcwd(), "app", "uploads")
#     if os.path.exists(folder_path) and os.path.isdir(folder_path):
#         items = os.listdir(folder_path)

#         files = [
#             item for item in items if item.startswith("test")
#             and os.path.isfile(os.path.join(folder_path, item))
#         ]

#         if len(files) > 0:
#             for file in files:
#                 os.remove(os.path.join(folder_path, file))
#     assert True

#     folder_path = os.path.join(os.getcwd(), "app", "out-files")
#     if os.path.exists(folder_path) and os.path.isdir(folder_path):
#         items = os.listdir(folder_path)

#         files = [
#             item for item in items if item.startswith("test")
#             and os.path.isfile(os.path.join(folder_path, item))
#         ]

#         if len(files) > 0:
#             for file in files:
#                 os.remove(os.path.join(folder_path, file))
#     assert True


# def test_get_template_generate_page(client):
#     response = client.get('/template-generate')
#     assert response.status_code == 200
#     assert b'Vulnerability Scanner Template Generator' in response.data
