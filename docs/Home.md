# Welcome to the AdminGuard: Strengthening OS Security from Within Wiki

## :thought_balloon: What is AdminGuard?

AdminGuard is a Web Application Tool which allows users to read, modify and generate scripts for fixing and checking based on the Security Technical Implementation Guide (STIG) provided by The DoD Cyber Exchange. To download the STIG guides, the following link can be used https://public.cyber.mil/stigs/downloads/  
The tool also allows users to modify the Tenable Nessus Template file based on the user's STIG file. The Tenable Nessus Template File can be downloaded from the following link https://www.tenable.com/downloads/download-all-compliance-audit-files  

## :clipboard: Table Of Content

- [Welcome to the AdminGuard: Strengthening OS Security from Within Wiki](#welcome-to-the-adminguard-strengthening-os-security-from-within-wiki)
  - [:thought\_balloon: What is AdminGuard?](#thought_balloon-what-is-adminguard)
  - [:clipboard: Table Of Content](#clipboard-table-of-content)
- [Ways to Run :runner:](#ways-to-run-runner)
- [Running Dockerized :whale:](#running-dockerized-whale)
- [Native installation](#native-installation)
  - [Cloning AdminGuard Repository](#cloning-adminguard-repository)
  - [Automated Installation](#automated-installation)
  - [Manual Installation](#manual-installation)
    - [Installing Python](#installing-python)
    - [Installing Python Dependencies](#installing-python-dependencies)
  - [:arrow\_forward: Running the Web Application](#arrow_forward-running-the-web-application)
- [Project Structure](#project-structure)


# Ways to Run :runner:
    
    1. Using Docker, which is the preferred option
    2. Native installation

# Running Dockerized :whale:

```
# clone repository
git clone https://github.com/C4RR0T02/CSIT_AdminGuard_Website.git

# access the AdminGuard directory
cd CSIT_AdminGuard_Website

# build the Dockerfile
docker build -t adminguard_flask .

# run the Dockerfile
docker run -p 8080:8080 adminguard_flask
```

# Native installation

## Cloning AdminGuard Repository

```
# clone repository
git clone https://github.com/C4RR0T02/CSIT_AdminGuard_Website.git

# access the AdminGuard directory
cd CSIT_AdminGuard_Website
```

## Automated Installation

Execute the installation package with the following commands

Windows: 
```
bash install.sh
```

Linux: 
```
chmod +x install.sh
./install.sh
```

## Manual Installation

To host AdminGuard on the device, the core requirements are as follows

- Clone AdminGuard Repository
- Install Python
- Install Python dependencies

### Installing Python

Note: Python 3.10+ is required!

The Python 3.10 version can be downloaded from the official python website https://www.python.org/downloads/release/python-3100/ 

### Installing Python Dependencies 

There's also a pip requirements.txt for pip users:

```
pip install -r requirements.txt
```

## :arrow_forward: Running the Web Application 

To run the Python Flask Server, execute the following commands

```
python -m flask --app .\app\app.py run
```

Navigate to the following site on your browser

```
http://<your ip address>:<port>
```

![AdminGuard Home Page](https://github.com/C4RR0T02/CSIT_AdminGuard_Website/blob/main/wiki/images/select_tool.jpg)

# Project Structure

```
.  
├── app                                 # Application Files  
│   ├── script                          # Back-End Logic of Application  
│   │   ├── __init.py__  
│   │   ├── nessusaudit.py              # Audit File to Python Object Script  
│   │   ├── powershell_commands.txt     # List of Valid Commands in PowerShell File  
│   │   ├── stig_script_gen.py          # STIG Script Generator Script  
│   │   └── template_gen.py             # Template Generator Script  
│   ├── static                          # Bootstrap  
│   ├── templates                       # Front-End Pages
│   ├── tests                           # Automated tests and test files  
│   ├── __init.py__         
│   └── app.py                          # Flask application  
├── docs                                # Documentation files  
├── installations                       # Installation files   
│   └── install.sh  
├── wiki                                # Wiki Images  
│   └── images  
├── Dockerfile                             
├── flake8_config.txt                   # Flake8 Config File (Rename to .flake8)  
├── README.md  
└── requirements.txt  
```
