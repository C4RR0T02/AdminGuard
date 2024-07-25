# Vulnerability Scanner Template Generator

## :clipboard: Table Of Content

- [Vulnerability Scanner Template Generator](#vulnerability-scanner-template-generator)
  - [:clipboard: Table Of Content](#clipboard-table-of-content)
  - [Description](#description)
  - [Features and Capabilities](#features-and-capabilities)
    - [Customization of Audit Checks](#customization-of-audit-checks)
    - [Generation of Updated Audit File](#generation-of-updated-audit-file)
    - [Offline Access](#offline-access)
    - [Scalability](#scalability)
    - [Improve Time and Resource Efficiency](#improve-time-and-resource-efficiency)
  - [Usage](#usage)
  - [Limitations](#limitations)
    - [1. Files not Cached](#1-files-not-cached)
    - [2. Files are not scanned](#2-files-are-not-scanned)
    - [3. Not all items are detected](#3-not-all-items-are-detected)
  - [Possible Improvements](#possible-improvements)
    - [Caching of files](#caching-of-files)
    - [File Scanning](#file-scanning)
    - [File storage for previously generated files](#file-storage-for-previously-generated-files)
    - [Modification of multiple Template files](#modification-of-multiple-template-files)
    - [Integration of Template Generation with STIG File Generation](#integration-of-template-generation-with-stig-file-generation)
    - [Make use of UI similar to Scratch](#make-use-of-ui-similar-to-scratch)

## Description
The vulnerability scanner template generator takes in a `file` and the `type` of template file. The `audit` file is than processed and presented to the users for editing. After the editing is completed, the updated audit file is generated. 

The template file is required to be an `audit` file and the file size is to be below `50 MegaBytes`.

## Features and Capabilities

1. [Customization of Audit Checks](#Customization-of-Audit-Checks)
2. [Generation of Updated Audit File](Generation-of-Updated-Audit-File)
3. [Offline Access](Offline-Access)
4. [Scalability](Scalability)
5. [Improve Time and Resource Efficiency](#improve-time-and-resource-efficiency)

### Customization of Audit Checks

Different Organisations may have different requirements to meet to fulfil the Data Protection Regulations applicable to the industry.

The audit file allows users to specify the various vulnerabilities and the command, regex and or powershell arguments to check for system compliance. 

With the audit file being generated with the content of the fields displayed to the end user, end-users are able to compare and make modification to the audit file based on the company regulations and the STIG guide. 

![Template Generator - Customize Template File](https://github.com/C4RR0T02/AdminGuard/blob/main/wiki/images/customize_template_file.png)

### Generation of Updated Audit File

After customising the various rules checking details, an updated audit file with the information edited by the user is generated.  This file can be uploaded into the Nessus Vulnerability Scanner to perform compliance checking. 

### Offline Access

This web application does not need to be connected to the internet as it does not make use of content distribution network (CDN). Instead, all files which are required are downloaded and referenced within the various pages. 

This will ensure that even without internet or within an intranet, the application is able to function without disruption. 

### Scalability

Docker containers provide a lightweight and consistent environment for applications, making it easier to manage and scale. Docker containers share the host operating system's kernel, making them more resource-efficient than traditional virtual machines. 

The docker image that is created using the docker file can be used to create docker containers. This docker image can be easily deployed into multiple docker container allowing it to easily scale up and down based on the demands of the users. 

### Improve Time and Resource Efficiency

Editing the Vulnerabily Scanner Template file based on STIG guidelines can be time-consuming and error-prone. With the information scattered all over the file and not easily understandable, the template generator simplifies this process, saving time and resources for both security professionals and system administrators.

## Usage

1. Select Vulnerability Scanner Template Converter

![AdminGuard - Select Tool](https://github.com/C4RR0T02/AdminGuard/blob/main/wiki/images/select_tool.jpg)

2. Upload the Nessus Template file that can be downloaded from this [link](https://www.tenable.com/downloads/download-all-compliance-audit-files) and select the type of template file

![Template Generator - Upload Template File](https://github.com/C4RR0T02/AdminGuard/blob/main/wiki/images/upload_template_file.png)

3. Once the file has been successfully uploaded, the check values can be edited

![Template Generator - Customize Template File](https://github.com/C4RR0T02/AdminGuard/blob/main/wiki/images/customize_template_file.png)

4. Once all rules have be reviewed, the Generate Template button, once clicked will redirect to the Template download page

![Template Generator - Download Files](https://github.com/C4RR0T02/AdminGuard/blob/main/wiki/images/download_template_file.png)

## Limitations

1. [Files are not cached](#1-files-not-cached)
2. [Files are not scanned](#2-files-are-not-scanned)
3. [Not all items are detected](#3-not-all-items-are-detected)


### 1. Files not Cached

While the user is able to upload the file and the file is passed between each page, if the server is restarted, the files though stored within the system will cause an error due to the dictionary not storing the data of all files previously uploaded within the system. 

When the same file is uploaded within the system, the data is also reprocessed making the users wait while the content of the file may be the same as the previous file uploaded. 

This limitation can be tackled by implementing a [caching for files](#caching-of-files).

### 2. Files are not scanned

While the file type along with the size of the file uploaded by the users are checked, the file content are not checked for any malicious intent. As such if a user is to upload a file that is able to bypass the xml checks and below the set file size, the file will be executed within the system to perform the script which will be detrimental. 

While the effects are not really seen when deploying on a docker container, if the application is installed locally on a system to be deployed, Confidentiality, Integrity, and Availability will be impacted.

Confidentiality:

```
Attackers will get unauthorised access to any sensitive information generated
```

Integrity:

```
Attackers may upload malicious scripts or code that could alter or manipulate data within the system. 
```

Availability:

```
Attackers might upload a file containing a denial-of-service (DoS) attack that consumes system resources, leading to service disruptions
```

### 3. Not all items are detected

While the program makes use of an external repository code on the audit file being converted to python objects, not all items are picked up for the Windows file. 

This results in some of the newly edited fields not being saved completely.

## Possible Improvements

1. [Caching of files](#caching-of-files)  
2. [File Scanning](#file-scanning)  
3. [File storage for previously generated files](#file-storage-for-previously-generated-files)  
4. [Modification of multiple Template files](#modification-of-multiple-template-files)  
5. [Integration of Template Generation with STIG File Generation](#integration-of-template-generation-with-stig-file-generation)  
6. [Make use of UI similar to Scratch](#make-use-of-ui-similar-to-scratch)  

### Caching of files

The caching of files will enable users to quickly load file with the same content on the server faster. It will also help to load the data of the files into the dictionary after the server restarts. This will ensure that the files will be able to be quickly used by the end users and not have to wait and upload the file again.

### File Scanning

Making use of not just a extension checker as well as a file size checker, other information of the files uploaded should also be checked. These could possibly be an antivirus scan making use of antiviruses similar to VirusTotal APIs to check and scan the file to ensure the file is not malicious or holds malicious code. 

By scanning the uploaded files, the chances of malicious files and code executions are significantly reduced. 

### File storage for previously generated files

Foreseeing there will be many files that are generated by users concurrently, a proper file storage can be set up recording the guide information as well as the creation time to be able to plot it within a table which will allow users to download past scripts created by the users. 

### Modification of multiple Template files 

Instead of requiring users to restart the process and edit multiple template one at a time, the application can be modified to allow users to upload multiple template files and various pages to allow the users to quickly modify the rules at once before being able to generate all the various templates categorised by the name of the template and zipped into one folder for the users to easily audit and modify the files. 

### Integration of Template Generation with STIG File Generation

The integration of the template generation and the STIG file generation will allow the engineers to be able to view and modify the rule and check content required by the template generation at the same time. This will allow the cross checking of rule details between the file.

### Make use of UI similar to Scratch

The usage of a UI similar to scratch will allow the engineers to add additional checks towards the template files. The engineers will also be able to modify the logic of checks from the UI without requiring to modify the file content directly. This will allow engineers new to the team to be able to modify the content and understand the content easily. 
