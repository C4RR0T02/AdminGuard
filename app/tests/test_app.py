import os
import pytest
import shutil
from io import BytesIO
from ..app import app

root_dir = os.getcwd()


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
        assert b'''<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-V-230222" aria-expanded="true" aria-controls="collapse-V-230222">''' in response.data


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
        assert b'''<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-V-254239" aria-expanded="true" aria-controls="collapse-V-254239">''' in response.data


def test_script_fields_get_invalid(client):
    shutil.copyfile(
        'app/tests/testFiles/test_windows_2.xml',
        os.path.join(app.config['upload_folder'], 'test_windows_2.xml'))
    with open('app/tests/testFiles/test_windows_2.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_windows_2.xml')
    response = client.post('/script-generate',
                           data={
                               'guide_type': 'Linux',
                               'file': uploaded_file
                           })
    if response.status_code == 302:
        new_url = response.headers['Location']
        response = client.get(new_url)
        assert b'<input class="form-control" id="V-254243.check.0.[application account name]" name="V-254243.check.0.[application account name]" type="text" value="">\n' not in response.data


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


def test_script_fields_post_windows(client):
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
        response = client.post(new_url)
        if response.status_code == 302:
            new_url = response.headers['Location']
            response = client.get(new_url)
            assert response.status_code == 200


def test_script_download_get_page_linux(client):
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
            assert b'''<h1 class="text-center my-3 mx-auto">Download Scripts for test_linux_2</h1>''' in response.data


def test_script_download_get_page_windows(client):
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
        response = client.post(new_url)
        if response.status_code == 302:
            new_url = response.headers['Location']
            response = client.get(new_url)
            assert response.status_code == 200
            assert b'''<h1 class="text-center my-3 mx-auto">Download Scripts for test_windows_2</h1>''' in response.data


def test_download_file_linux(client):
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
            if response.status_code == 200:
                check_script_url = '/script-generate/test_linux_2/download/checkscript'
                response = client.get(check_script_url)
                assert response.status_code == 200
                fix_script_url = '/script-generate/test_linux_2/download/fixscript'
                response = client.get(fix_script_url)
                assert response.status_code == 200
                manual_check_url = '/script-generate/test_linux_2/download/manualcheck'
                response = client.get(manual_check_url)
                assert response.status_code == 200
                manual_fix_url = '/script-generate/test_linux_2/download/manualfix'
                response = client.get(manual_fix_url)
                assert response.status_code == 200
                new_guide_url = '/script-generate/test_linux_2/download/newguide'
                response = client.get(new_guide_url)
                assert response.status_code == 200
                zip_file_url = '/script-generate/test_linux_2/download/zipped'
                response = client.get(zip_file_url)
                assert response.status_code == 200


def test_download_file_windows(client):
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
        response = client.post(new_url)
        if response.status_code == 302:
            new_url = response.headers['Location']
            response = client.get(new_url)
            if response.status_code == 200:
                check_script_url = '/script-generate/test_windows_2/download/checkscript'
                response = client.get(check_script_url)
                assert response.status_code == 200
                fix_script_url = '/script-generate/test_windows_2/download/fixscript'
                response = client.get(fix_script_url)
                assert response.status_code == 200
                manual_check_url = '/script-generate/test_windows_2/download/manualcheck'
                response = client.get(manual_check_url)
                assert response.status_code == 200
                manual_fix_url = '/script-generate/test_windows_2/download/manualfix'
                response = client.get(manual_fix_url)
                assert response.status_code == 200
                new_guide_url = '/script-generate/test_windows_2/download/newguide'
                response = client.get(new_guide_url)
                assert response.status_code == 200
                zip_file_url = '/script-generate/test_windows_2/download/zipped'
                response = client.get(zip_file_url)
                assert response.status_code == 200


def test_download_invalid_file(client):
    shutil.copyfile(
        'app/tests/testFiles/test_linux_4.xml',
        os.path.join(app.config['upload_folder'], 'test_linux_4.xml'))
    with open('app/tests/testFiles/test_linux_4.xml', 'rb') as file:
        uploaded_file = (BytesIO(file.read()), 'test_linux_4.xml')
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
            if response.status_code == 200:
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'test_linux_4-CheckScript.sh'))
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'test_linux_4-FixScript.sh'))
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'test_linux_4-ManualCheck.txt'))
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'test_linux_4-ManualFix.txt'))
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'updated-test_linux_4.xml'))
                os.remove(
                    os.path.join(app.config['download_folder'], 'test_linux_4',
                                 'test_linux_4.zip'))
                check_script_url = '/script-generate/test_linux_4/download/checkscript'
                response = client.get(check_script_url)
                assert response.status_code == 404
                fix_script_url = '/script-generate/test_linux_4/download/fixscript'
                response = client.get(fix_script_url)
                assert response.status_code == 404
                manual_check_url = '/script-generate/test_linux_4/download/manualcheck'
                response = client.get(manual_check_url)
                assert response.status_code == 404
                manual_fix_url = '/script-generate/test_linux_4/download/manualfix'
                response = client.get(manual_fix_url)
                assert response.status_code == 404
                new_guide_url = '/script-generate/test_linux_4/download/newguide'
                response = client.get(new_guide_url)
                assert response.status_code == 404
                zip_file_url = '/script-generate/test_linux_4/download/zipped'
                response = client.get(zip_file_url)
                assert response.status_code == 404


def test_remove_files():
    for folder in os.listdir(os.path.join(root_dir, "app", "out-files")):
        if folder.startswith("test"):
            shutil.rmtree(os.path.join(root_dir, "app", "out-files", folder))
    for file in os.listdir(os.path.join(root_dir, "app", "uploads")):
        if file.startswith("test"):
            os.remove(os.path.join(root_dir, "app", "uploads", file))


def test_get_template_generate_page(client):
    response = client.get('/template-generate')
    assert response.status_code == 200
    assert b'Vulnerability Scanner Template Generator' in response.data
