Search Shodan for devices then concurrently test all the results with the same credentials. Optionally specify a bit of HTML or text from the source of the logged-in homepage to see if the authentication succeeded. If no authentication is necessary, simpy print the IP and page title of the response. Capable of both HTTP Basic Auth as well as form logins with -f. Logs active devices to <your_shodan_search_terms>_results.txt

Default timeout on the requests is 12 seconds. Sends batches of 200 requests concurrently although you can adjust this limit on one line in the main function. 


Requirements:
-----

### Shodan API Key
Options
* Give the script the -api <YOUR API KEY> argument
* Edit line 61 to do it permanently and feel free to offer a pull request after you perform this so you have it in your records; safe hands and all ;)
Don't have an API key? Get one free easily [from shodan](http://www.shodanhq.com/account/register)... alternatively, explore your Google dorking skills before downloading some Shodan ones.

### Python 2.7
* mechanize
* gevents
* BeautifulSoup
* shodan

### Modern linux
* Test on Kali 1.0.6

Usage
-----

``` shell
python ./shodan_pharmer.py -s 'dd-wrt' -t -u root -p admin -f 'Advanced Routing'
```
Search Shodan for "dd-wrt" and attempt to login to the results using the username root and the password admin along with whether "Advanced Routing" appeared in the response html. Due to the addition of the -t for --textbox argument this will attempt to login using both a form sign-in page and HTTP Basic Auth if there aren't any forms in response. Without the -t option it will only attempt HTTP Basic Auth which will have minor performance benefits. You can put raw html in the -f argument as well.


``` shell
python ./shodan_pharmer.py -s 'dd-wrt'
```
Hit all the IPs in the Shodan results and return the status and the title if it responds.


``` shell
python ./shodan_pharmer.py -ip 192.168.1.1 
```
Try hitting a single device's IP address.


### All options:

-s SEARCH: search Shodan for term(s) and print each IP address, whether the page returned a response, and if so print the title of the returned page (follows redirects)

-f FINDTERMS: search for the argument string in the html of each response; upon a match print it and log it

-t: Try to find a form to login to on the response page and default back to HTTP Basic Auth if no forms are found 

-u USERNAME: attempt to login using this username

-p PASSWORD: attempt to login using this password

-ip IPADDRESS: try hitting this ip address rather than shodan search results and return response information

-api APIKEY: use this API key when searching Shodan

-u USERNAME: username to use with HTTP Basic Auth which is used because no -t


License
-------

Copyright (c) 2013, Dan McInerney
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
* [danmcinerney.org](danmcinerney.org)
* [![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=DanMcInerney&url=https://github.com/DanMcInerney/shodan_pharmer&title=shodan_pharmer&language=&tags=github&category=software) 
