import os
import shutil
from ..app import *

root_dir = os.getcwd()

# Create upload and download folders if they don't exist
upload_folder = os.path.join(root_dir, 'app', 'uploads')
if not os.path.isdir(upload_folder):
    os.mkdir(upload_folder)
if not os.path.isdir(os.path.join(upload_folder, 'stig')):
    os.mkdir(os.path.join(upload_folder, 'stig'))
if not os.path.isdir(os.path.join(upload_folder, 'vatemplate')):
    os.mkdir(os.path.join(upload_folder, 'vatemplate'))

download_folder = os.path.join(root_dir, 'app', 'out-files')
if not os.path.isdir(download_folder):
    os.mkdir(download_folder)



def test_remove_files():
    for folder in os.listdir(os.path.join(root_dir, "app", "out-files")):
        if folder.startswith("test"):
            shutil.rmtree(os.path.join(root_dir, "app", "out-files", folder))
    for file in os.listdir(os.path.join(root_dir, "app", "uploads")):
        if file.startswith("test"):
            os.remove(os.path.join(root_dir, "app", "uploads", file))
    for folder in os.listdir(os.path.join(root_dir, "app", "out-files",
                                          "zip")):
        if folder.startswith("test"):
            shutil.rmtree(
                os.path.join(root_dir, "app", "out-files", "zip", folder))
