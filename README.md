device-pharmer
======

Concurrently open either Shodan search results, a specified IP, IP range, domain, or list of IPs from a text file and print the status and title of the page if applicable. Add the -u and -p options to attempt to login to the page first looking for a form login and failing that, attempt HTTP Basic Auth. 

Use -f SEARCHSTRING to look for a certain string in the html response in order to test if authentication succeeded. Logs all devices that respond using either the Shodan search term or the target IPs/domain + _results.txt. One caveat with searching the response page's HTML is that some form login pages return a JSON object response after an authentication request rather than the post-login page's HTML source. Often you can determine whether or not you were successful by just using -f "success" in scenarios like this.

Default timeout on the requests is 15 seconds. Sends batches of 1000 requests concurrently which can be adjust using the -c option. One should note that Shodan only allows the first page of results (100 hosts) if you are using their free API key. If you have their professional API key you can specify the number of search result pages to test with the -n NUMBER_OF_PAGES argument. By default it will only check page 1.

Requirements:
-----
Python 2.7
* mechanize
* gevents
* BeautifulSoup
* shodan (if giving the -s option)

Modern linux
* Tested on Kali 1.0.6

Shodan API Key (only if you are giving the -s SEARCHTERM argument)
* Give the script the -a YOUR_API_KEY argument OR
* Edit line 82 to do it permanently and feel free to offer a pull request after you perform this so you have it in your records; safe hands and all ;). Don't have an API key? Get one free easily [from shodan](http://www.shodanhq.com/account/register)... alternatively, explore your Google dorking skills before downloading some Shodan ones.


Usage
-----

Simplest usage:
``` shell
python device-pharmer.py -s 'dir-300' -a Wutc4c3T78gRIKeuLZesI8Mx2ddOiP4
```
Search Shodan for "dir-300" using the API key Wutc4c3T78gRIKeuLZesI8Mx2ddOiP4. Print the IP and title of the response page should it exist.

``` shell
python device-pharmer.py -s 'dd-wrt' -a Wutc4c3T78gRIKeuLZesI8Mx2ddOiP4 -u admin -p password -n 5 -f ">Advanced Routing<" --proxy 123.12.12.123:8080 --timeout 30
```
Search Shodan for "dd-wrt" using the given api key and attempt to login to the results with the username "admin" and the password "password". Gather only the first 5 pages (500 hosts) of Shodan results and check if the landing page's HTML contains the string ">Advanced Routing<". Print "* MATCH *" along with the IP and title of the page in the output and log if the string is found. Finally, use an HTTP proxy at 123.12.12.123:8080 for all requests and set the timeout to 30s.


``` shell
python device-pharmer.py -t 192.168.0-2.1-100 -c 100
```
Targeting 192.168.0-2.1-100 is telling the script to concurrently open 192.168.0.1-101, 192.168.1.1-101, and 192.168.2.1-101 and to gather the status and title of the response pages. -c 100 will limit concurrency to 100 pages at a time so this script will pass through 3 groups of 100 IPs each. Since the default timeout within the script is 15 seconds this will take about ~45 seconds to complete.

``` shell
python device-pharmer.py -t www.reddit.com/login -ssl -u sirsmit418 -p whoopwhoop -f 'tattoos'
```
Try logging into www.reddit.com/login using HTTPS specifically with the username sirsmit418 and password whoopwhoop. Look for the text "tattoos" correlating to a subscribed subreddit in the response html to check for authentication success.

``` shell
python device-pharmer.py --ipfile list_of_ips.txt
```
Test each IP from a textfile of newline-separated IPs


### All options:

-a APIKEY: use this API key when searching Shodan (only necessary in conjunction with -s)

-c CONCURRENT: send a specified number of requests concurrently; default=1000

-f FINDTERMS: search for the argument string in the html of each response; upon a match print it and log it

--ipfile IPTEXTFILE: test each IP in a list of newline-separated IPs from the specified text file

-n NUMPAGES: go through specified amount of Shodan search result pages collecting IPs; 100 results per page

-p PASSWORD: attempt to login using this password

--proxy PROXY: use this proxy for making requests; to login to the proxy with HTTP Basic do something like, user:pass@123.12.12.123:8080

-s SEARCHTERMS: search Shodan for term(s) and print each IP address, whether the page returned a response, and if so print the title of the returned page (follows redirects)

-ssl: specifically send HTTPS requests to all targets 

-t IPADDRESS/DOMAIN/IPRANGE: try hitting this domain, IP, or IP range instead of using Shodan to populate the targets list and return response information

--timeout TIMEOUT: set the timeout for each URI in seconds; default is 15

-u USERNAME: attempt to login using this username


License
-------

Copyright (c) 2014, Dan McInerney
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Dan McInerney nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


***
* [danmcinerney.org](http://danmcinerney.org)
* [![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=DanMcInerney&url=https://github.com/DanMcInerney/device-pharmer&title=device-pharmer&language=&tags=github&category=software) 
