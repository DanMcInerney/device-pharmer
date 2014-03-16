#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Search Shodan for devices then concurrently test all the results with the same credentials.
Optionally specify a bit of HTML or text from the source of the logged-in homepage to see
if the authentication succeeded. If no authentication is necessary, simpy print the IP and
page title of the response. Capable of both HTTP Basic Auth as well as form logins with -f.
Logs active devices to <your_shodan_search_terms>_results.txt

Requires:   Linux
            Python 2.7
                gevents
                mechanize
                BeautifulSoup
                shodan


__author__ = Dan McInerney
             danmcinerney.org
             @danhmcinerney
'''

#This must be one of the first imports or else we get threading error on completion
from gevent import monkey
monkey.patch_all()

# Overzealously prevent mechanize's gzip warning
import warnings
warnings.filterwarnings("ignore")

import gevent
from shodan import WebAPI
import argparse
import mechanize
from BeautifulSoup import BeautifulSoup
import cookielib
from socket import setdefaulttimeout
# Mechanize doesn't respsect timeouts when it comes to reading/waiting for SSL info so this is necessary
setdefaulttimeout(12)

# Including lxml in case someone wants to use it instead of BeautifulSoup
#import lxml
#from lxml.html import fromstring

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-s", "--search", help="Your search terms")
   parser.add_argument("-f", "--findhtml", help="Search html for a string; can be used to determine if a login was successful")
   parser.add_argument("-u", "--username", help="Enter username after this arg")
   parser.add_argument("-p", "--password", help="Enter password after this arg")
   parser.add_argument("-ip", "--ipaddress", help="Enter a single IP to test")
   parser.add_argument("-t", "--textboxes", help="Enter this flag if the device has a form login with text/password boxes rather than HTTP basic auth", action='store_true')
   parser.add_argument("-api", "--apikey", help="Your api key")
   return parser.parse_args()

def shodan_search(search, apikey):
    if apikey:
        API_KEY = args.apikey
    else:
        API_KEY = 'ENTER YOUR API KEY HERE AND KEEP THE QUOTES'
    api = WebAPI(API_KEY)

    ips_found = []

    try:
        results = api.search('%s' % search)
        print '[+] Results: %s' % results['total']
        for r in results['matches']:
            ips_found.append(r['ip'])
        return ips_found
    except Exception as e:
        print '[!] Error:', e

def browser_mechanize():
    ''' Start headless browser '''
    br = mechanize.Browser()
    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)
    # Browser options
    br.set_handle_equiv(True)
    br.set_handle_gzip(True)
    br.set_handle_redirect(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)
    # Follows refresh 0 but not hangs on refresh > 0
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko')]
    return br

class Scraper():

    def __init__(self, args):
        #self.args = args
        self.user = args.username
        self.passwd = args.password
        self.textboxes = args.textboxes
        self.findhtml = args.findhtml
        self.search = args.search
        self.br = browser_mechanize()

    def run(self, ip):
        try:
            resp = self.req(ip)
            title, match = self.html_parser(resp)
            if match:
                mark = '+'
                label = match
            else:
                mark = '*'
                label = 'Title:    '
            sublabel = title
        except Exception as e:
            mark = '-'
            label = 'Exception:'
            sublabel = str(e)

        self.final_print(mark, ip, label, sublabel)

    def req(self, ip):
        ''' Determine what type of auth to use, if any '''
        if self.user and self.passwd:
            if self.textboxes:
                return self.resp_to_textboxes(ip)
            else:
                return self.resp_basic_auth(ip)
        return self.resp_no_auth(ip)

    #############################################################################
    # Get response functions
    #############################################################################
    def resp_no_auth(self, ip):
        ''' No username/password argument given '''
        no_auth_resp = self.br.open('http://%s' % ip)
        return no_auth_resp

    def resp_basic_auth(self, ip):
        ''' When there are username/password arguments but no --textboxes arg '''
        self.br.add_password('http://%s' % ip, self.user, self.passwd)
        basic_auth_resp = self.br.open('http://%s' % ip)
        return basic_auth_resp

    def resp_to_textboxes(self, ip):
        ''' Find first input with type=text
        then first input with type=password.
        If form login fails, try basic auth
        and if that fails, try no auth '''

        try:
            resp = self.br.open('http://%s' % ip)
            self.br.form = list(self.br.forms())[0]
            resp = self.fill_out_form()
        except Exception as e:
            try:
                resp = self.resp_basic_auth(ip)
            except Exception as e:
                resp = self.resp_no_auth(ip)

        return resp

    def fill_out_form(self):
        ''' Find the first text and password controls and fill them out '''
        text_found = 0
        pw_found = 0
        for c in self.br.form.controls:
            if c.type == 'text':
                # Only get the first text control box
                if text_found == 0:
                    c.value = self.user
                    text_found = 1
                    continue
            if c.type == 'password':
                c.value = self.passwd
                pw_found = 1
                break

        form_resp = self.br.submit()
        return form_resp
    #############################################################################

    def html_parser(self, resp):
        ''' Parse html, look for a match with user arg
        and find the title. '''
        html = resp.read()

        # Find match
        match = self.find_match(html)

       # Including lxml in case someone has more success with it
       # My test showed that BeautifulSoup encountered a few less encoding errors (3 vs 5 from lxml)
       # root = fromstring(html)
       # find_title = root.xpath('//title')
       # try:
       #     title = find_title[0].text
       # except Exception as e:
       #     title = '<None>'

        # Get title
        soup = BeautifulSoup(html)
        try:
            title = soup.title.string
        except Exception as e:
            title = '<None found>'

        return title, match

    def find_match(self, html):
        match = None
        if self.findhtml:
            if self.findhtml in html:
                match = '* MATCH * '
        return match

    def final_print(self, mark, ip, label, sublabel):
        try:
            results = '[%s] %s | %s %s' % (mark, ip.ljust(15), label, sublabel)
            if mark == '*' or mark == '+':
                with open('%s_results.txt' % self.search, 'a') as f:
                    f.write('%s\n' % results)
            print results
        except Exception as e:
            results = '[%s] %s | %s %s' % (mark, ip.ljust(15), label, str(e))
            with open('%s_results.txt' % self.search, 'a') as f:
                f.write('%s\n' % results)
            print results


def main(args):

    S = Scraper(args)

    if args.ipaddress:
        ips = ['%s' % args.ipaddress]
    else:
        ips = shodan_search(args.search, args.apikey)

    # Run 200 concurrently at a time
    ip_groups = [ips[x:x+200] for x in xrange(0, len(ips), 200)]

    for chunk_ips in ip_groups:
        jobs = [gevent.spawn(S.run, ip) for ip in chunk_ips]
        gevent.joinall(jobs)

if __name__ == "__main__":
    main(parse_args())
