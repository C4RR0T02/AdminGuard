#! /bin/bash

# Function to install dependencies on Linux
install_linux_dependencies() {
    # Install Python 3.10
    sudo apt-get update
    sudo apt-get install -y python3.10 python3-pip

    # Install additional dependencies from requirements.txt
    pip3 install -r requirements.txt
}

# Function to install dependencies on macOS
install_macos_dependencies() {
    # Install Homebrew if not installed
    if ! command -v brew &> /dev/null; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi

    # Install Python 3.10
    brew install python@3.10

    # Install additional dependencies from requirements.txt
    pip3 install -r requirements.txt
}

# Function to install dependencies on Windows
install_windows_dependencies() {
    # Install Python 3.10 using the official installer
    # You may need to adjust the installation path
    choco install python3 --params "/InstallDir:C:\Program Files\Python310" -y

    # Install additional dependencies from requirements.txt
    pip install -r requirements.txt
}

# Detect the operating system
case "$(uname -s)" in
    Linux*) install_linux_dependencies ;;
    Darwin*) install_macos_dependencies ;;
    CYGWIN*|MINGW*) install_windows_dependencies ;;
    *) echo "Unsupported operating system." ;;
esac
