Search Shodan for devices then concurrently test all the results with the same credentials.
Optionally specify a bit of HTML or text from the source of the logged-in homepage to see
if the authentication succeeded. If no authentication is necessary, simpy print the IP and
page title of the response. Capable of both HTTP Basic Auth as well as form logins with -f.
Logs active devices to <your_shodan_search_terms>_results.txt
