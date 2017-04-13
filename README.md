# XSSor
XSSor is a semi-automatic reflected and persistent XSS detector extension for Burp Suite. The tool was written in Python by Barak Tawily, an application security expert. XSSor was designed to help security testers by performing semi-automatic reflected and persistent XSS detection tests.
 
![alt tag](https://raw.githubusercontent.com/Quitten/XSSor/master/xssor.jpg)
 
# Installation 
1.     Download Burp Suite (obviously): http://portswigger.net/burp/download.html
2.     Download Jython Standalone JAR: http://www.jython.org/downloads.html
3.     Open BurpàExtenderà Optionsà Python Environmentà Select Fileà Choose the Jython Standalone JAR
4.     To install XSSor follow these steps:
a.     Download the XSSor.py file.
b.     Open BurpàExtenderà Extensionsà Addà Choose XSSor.py file.
c.     See the XSSor tab and enjoy semi-automatic reflected and persistent XSS detection J
 
# User guide - how to use?
1.     After installation, the XSSor tab will be added to Burp.
2.     Open the configuration tab (XSSorà Configuration) and turn XSSor on.
3.     Browse to the tested website and write the XSS keyword (the default is “xssme” in the tested parameter).
4.     XSSor will send the same request (or multiple requests if in ‘brute force’ mode) to the tested website with the defined payload (or multiple payloads in case of BT mode).
5.     XSSor will add a row for each payload, and the status; if it is vulnerable or not.
 
# Vulnerable status column
There are 3 options:

1.     N - Not vulnerable
2.     Yes (Reflected XSS) - The malicious payload was found in the response of the tested page.
3.     Yes (Persistent XSS) - The malicious payload was found in the response of one of the affected pages.
 
# Affected pages
The ‘affected pages’ feature was designed in order to find persistent XSS flaws. By adding this feature, XSSor will check if the malicious payload is found in the affected page’s responses.
 
In order to add affected pages, right-click on the request and click on ‘XSSor: Add affected page’ as shown in the following image:

![alt tag](https://raw.githubusercontent.com/Quitten/XSSor/master/add_affected_page.jpg)
 
You can view the affected page response and the request containing the payload in the ‘affected pages’ tab under the XSSor tab.

# Authors
- Barak Tawily, application security expert
 
