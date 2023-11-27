# AdminGuard: Strengthening OS Security from Within

## :thought_balloon: What is AdminGuard?

AdminGuard is a Web Application Tool which allows users to read, modify and generate scripts for fixing and checking based on the Security Technical Implementation Guide (STIG) provided by The DoD Cyber Exchange. To download the STIG guides, the following link can be used https://public.cyber.mil/stigs/downloads/

![AdminGuard-frontend](app/static/img/AdminGuardHomePage.jpg)

## :clipboard: Table Of Content

- [AdminGuard: Strengthening OS Security from Within](#adminguard-strengthening-os-security-from-within)
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

![AdminGuard Home Page](/app/static/img//select_tool.jpg)
