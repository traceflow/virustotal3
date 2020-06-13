""" VirusTotal API v3 Core

Module to interact with the Core part of the API.
"""
import os
import base64
import json
import time
import requests
import virustotal3.errors

VirusTotalApiError = virustotal3.errors.VirusTotalApiError

def _raise_exception(response):
    """Raise Exception

    Function to raise an exception using the error messages returned by the API.

    Parameters:
        response (dict) Reponse containing the error returned by the API.
    """
    # https://developers.virustotal.com/v3.0/reference#errors
    raise VirusTotalApiError(response.text)


def get_analysis(api_key, analysis_id, proxies=None, timeout=None):
    """Retrieve information about an analysis

    Parameters:
        api_key (str): VirusTotal API key
        analysis_id (str): Analysis ID to retrieve
        proxies (dict, optional): Dictionary containing proxies
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.
    """

    try:
        response = requests.get('https://www.virustotal.com/api/v3/analyses/{}'.format(analysis_id),
                                headers={'x-apikey': api_key,
                                         'Accept': 'application/json'},
                                proxies=proxies,
                                timeout=timeout)
        if response.status_code != 200:
            _raise_exception(response)

        return response.json()

    except requests.exceptions.RequestException as error:
        print(error)
        exit(1)

class Files:
    """Class for the Files endpoints
    """
    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Files class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary containing proxies

        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/files'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

        if api_key is None:
            raise Exception("You must provide a valid API key")

    def upload(self, sample, timeout=None):
        """Upload a file. 
        
        The size of the file will be calculated and the endpoint to use will be determined based on the file size.

        Parameters:
            sample (str): Path to file sample to upload
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the analysis ID
        """
        if not os.path.isfile(sample):
            raise Exception('File not found. Please submit an existing file.')

        # Calculate file size to determine which endpoint to use
        file_size = os.path.getsize(sample)

        if file_size < 33554432:
            with open(sample, 'rb') as f:
                data = {'file': f.read()}

                try:
                    response = requests.post(self.base_url,
                                             headers=self.headers,
                                             files=data,
                                             proxies=self.proxies,
                                             timeout=timeout)

                    if response.status_code != 200:
                        _raise_exception(response)

                    return response.json()

                except requests.exceptions.RequestException as error:
                    print(error)
                    exit(1)

        if file_size >= 33554432:
            with open(sample, 'rb') as f:
                data = {'file': f.read()}

                try:
                    # Get the upload URL first
                    response = requests.get(self.base_url + '/upload_url',
                                            headers=self.headers,
                                            proxies=self.proxies,
                                            timeout=timeout)

                    if response.status_code != 200:
                        _raise_exception(response)

                    upload_url = response.json()['data']

                    # Submit file to URL
                    response = requests.post(upload_url,
                                             headers=self.headers,
                                             files=data,
                                             proxies=self.proxies,
                                             timeout=timeout)

                    if response.status_code != 200:
                        _raise_exception(response)

                    return response.json()

                except requests.exceptions.RequestException as error:
                    print(error)
                    exit(1)

    def info_file(self, file_hash, timeout=None):
        """Retrieve information on a file

        Parameters:
            file_hash (str): File hash of the file
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing information about the file.
        """
        try:
            response = requests.get(self.base_url + '/{}'.format(file_hash),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def analyse_file(self, file_hash, timeout=None):
        """Re-analyse a file already in VirusTotal.

        Parameters:
            file_hash (str): File hash to re-analyse
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the analysis ID.
        """
        try:
            response = requests.post(self.base_url + '/{}/analyse'.format(file_hash),
                                     headers=self.headers,
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_comments(self, file_hash, limit=None, cursor=None, timeout=None):
        """Retrieve comments for a file

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the comments retrieved.
        """
        params = {'limit': limit, 'cursor': cursor}
        try:
            response = requests.get(self.base_url + '/{}/comments'.format(file_hash),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def add_comment(self, file_hash, comment, timeout=None):
        """Add a comment to a file

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            data (dict): Comment to add as dictionary. The package will take care of creating the JSON object.
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the added comment.
        """
        try:
            response = requests.post(self.base_url + '/{}/comments'.format(file_hash),
                                     headers=self.headers,
                                     data=json.dumps(comment),
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_votes(self, file_hash, limit=None, cursor=None, timeout=None):
        """Retrieve votes for a file

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the votes. The votes are located in the 'value' key.
        """
        params = {'limit': limit, 'cursor': cursor}
        try:
            response = requests.get(self.base_url + '/{}/votes'.format(file_hash),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def add_vote(self, file_hash, verdict, timeout=None):
        """Adds a verdict (vote) to a file. The verdict can be either 'malicious' or 'harmless'.

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            verdict (str): 'malicious' (-1) or 'harmless' (+1)
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the submitted vote.
        """
        verdicts = ['malicious', 'harmless']

        if verdict not in verdicts:
            raise Exception('Verdict must be harmless or malicious')

        data = {
            'data': {
                'type': 'vote',
                'attributes': {
                    'verdict': verdict
                }
            }
        }
        try:
            response = requests.post(self.base_url + '/{}/votes'.format(file_hash),
                                     headers=self.headers,
                                     data=json.dumps(data),
                                     proxies=self.proxies,
                                     timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.text

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def download(self, file_hash, output_dir='./', timeout=None):
        """Download a file for a given file hash.

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            output_dir (str, optional): Output directory, current working directory by default.
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            None
        """

        try:
            # Get download URL
            response = requests.get(self.base_url + '/{}/download_url'.format(file_hash),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            download_url = response.json()['data']

            # Download file
            response = requests.get(download_url,
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            with open(output_dir + '{}.bin'.format(file_hash), 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_relationship(self, file_id, relationship, limit=None, cursor=None, timeout=None):
        """Retrieve an object related to a file

        Parameters:
            file_hash (str): File hash (SHA256, MD5, SHA1)
            relationsip (str): Relationship object to retrieve. Can be one of the following:

                               analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, comments,
                               compressed_parents, comments, contacted_domains, contacted_ips, contacted_urls,
                               email_parents, embedded_domains, embedded_ips, execution_parents, graphs, itw_urls,
                               overlay_parents, pcap_parents, pe_resource_parents, similar_files, submissions,
                               screenshots, votes

                                For further details, see:
                                https://developers.virustotal.com/v3.0/reference#files-relationships

            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing the relationship object.
        """

        relationships = ['analyses', 'behaviours', 'bundled_files', 'carbonblack_children',
                         'carbonblack_parents', 'comments', 'compressed_parents', 'comments',
                         'contacted_domains', 'contacted_ips', 'contacted_urls', 'email_parents',
                         'embedded_domains', 'embedded_ips', 'execution_parents', 'graphs',
                         'itw_urls', 'overlay_parents', 'pcap_parents', 'pe_resource_parents',
                         'similar_files', 'submissions', 'screenshots', 'votes']

        if relationship not in relationships:
            raise Exception('Invalid relationship.')

        params = {'limit': limit, 'cursor': cursor}

        try:
            response = requests.get(self.base_url + '/{}/{}'.format(file_id, relationship),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)


class URL:
    """Class for the URL endpoints
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the URL class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary containing proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/urls'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

        if api_key is None:
            raise Exception("You must provide a valid API key")

    def info_url(self, url, timeout=None):
        """Retrieve information about a URL. If the URL was previously scanned, results will be returned immediately.
        Otherwise, a URL scan will begin and results might take a few seconds to return.

        Parameters:
            url (str): URL to scan
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the scan results.
        """
        try:
            # Send the URL to scan
            response = requests.post(self.base_url,
                                     headers=self.headers,
                                     data={'url': url},
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            # The API documentation states that we can fetch the scan results using either
            # the analysis ID returned by the first POST request, without the padding, or
            # by sending a GET request with the URL encoded in Base64, also without the padding.
            # Because the padding is easier to remove with Base64 (doesn't require regular expressions),
            # we use the encoded URL instead of the analysis ID.
            # Reference: https://developers.virustotal.com/v3.0/reference#url-info
            encoded_url = base64.b64encode(url.encode())
            response = requests.get(self.base_url + '/{}'.format(encoded_url.decode().replace('=', '')),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            # Wait for the analysis to finish before returning the results by looking at the content
            # of the 'last_analysis_results' key-value pair. If the value is empty, then the analysis
            # is not finished.
            while not response.json()['data']['attributes']['last_analysis_results']:
                response = requests.get(self.base_url + '/{}'.format(encoded_url.decode().replace('=', '')),
                                        headers=self.headers,
                                        proxies=self.proxies,
                                        timeout=timeout)
                time.sleep(3)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_votes(self, url, limit=None, cursor=None, timeout=None):
        """Retrieve votes for a URL

        Parameters:
            url (str): URL identifier
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the votes. The votes are located in the 'value' key.
        """
        params = {'limit': limit, 'cursor': cursor}
        try:
            encoded_url = base64.b64encode(url.encode())
            response = requests.get(self.base_url + '/{}/votes'.format(encoded_url.decode().replace('=', '')),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def add_vote(self, url, verdict, timeout=None):
        """Add a verdict to a URL

        Adds a verdict (vote) to a URL. The verdict can be either 'malicious' or 'harmless'.

        Parameters:
            url (str): URL identifier
            verdict (str): 'malicious' (-1) or 'harmless' (+1)
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing the submitted vote.
        """
        verdicts = ['malicious', 'harmless']

        if verdict not in verdicts:
            raise Exception('Verdict must be harmless or malicious')

        data = {
            'data': {
                'type': 'vote',
                'attributes': {
                    'verdict': verdict
                }
            }
        }

        try:
            encoded_url = base64.b64encode(url.encode())
            response = requests.post(self.base_url + '/{}/votes'.format(encoded_url.decode().replace('=', '')),
                                     headers=self.headers,
                                     data=json.dumps(data),
                                     proxies=self.proxies,
                                     timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.text

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_network_location(self, url, timeout=None):
        """Retrieve associated IPs and DNS records, site categories, and WHOIS info for a given URL.

        Parameters:
           url (str): URL identifier
           timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the details of a URL, including its latest DNS records and IP addresses.
        """
        try:
            encoded_url = base64.b64encode(url.encode())
            response = requests.get(self.base_url + '/{}/network_location'\
                                    .format(encoded_url.decode().replace('=', '')),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_relationship(self, url, relationship, limit=None, cursor=None, timeout=None):
        """Retrieve information on an object for a given URL identifier.

        Parameters:
            url (str): URL identifier
            relationship (str): Relationship object to retrieve. Can be one of the following:
                                analyses, downloaded_files, graphs, last_serving_ip_address,
                                redirecting_urls, submissions
            limit (str, optional): Limit of results to return
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the relationship object.
        """
        try:
            encoded_url = base64.b64encode(url.encode())
            params = {'limit': limit, 'cursor': cursor}
            response = requests.get(self.base_url + '/{}/{}'\
                                    .format(encoded_url.decode().replace('=', ''), relationship),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)


class Domains:
    """Class for the Domains endpoints
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Domains class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary containing proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/domains'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

        if api_key is None:
            raise Exception("You must provide a valid API key")

    def info_domain(self, domain, timeout=None):
        """Retrieve information about a domain

        Parameters:
            domain (str): Domain to scan
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the scan results.
        """
        try:
            response = requests.get(self.base_url + '/{}'.format(domain),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_votes(self, domain, limit=None, cursor=None, timeout=None):
        """Retrieve votes for a domain

        Parameters:
            domain (str): Domain
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the votes. The votes are located in the 'value' key.
        """
        params = {'limit': limit, 'cursor': cursor}
        try:
            response = requests.get(self.base_url + '/{}/votes'.format(domain),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def add_vote(self, domain, verdict, timeout=None):
        """Adds a verdict (vote) to a domain. The verdict can be either 'malicious' or 'harmless'.

        Parameters:
            domain (str): Domain
            verdict (str): 'malicious' (-1) or 'harmless' (+1)
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the submitted vote.
        """
        verdicts = ['malicious', 'harmless']

        if verdict not in verdicts:
            raise Exception('Verdict must be harmless or malicious')

        data = {
            'data':
                {
                    'type': 'vote', 'attributes':
                    {
                        'verdict': verdict
                    }
                }
            }
        try:
            response = requests.post(self.base_url + '/{}/votes'.format(domain),
                                     headers=self.headers,
                                     data=json.dumps(data),
                                     proxies=self.proxies,
                                     timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.text

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_relationship(self, domain, relationship, limit=None, cursor=None, timeout=None):
        """Retrieve objects related to a domain

        Parameters:
            url (str): URL identifier
            relationship (str): Relationship object to retrieve. Can be one of the following:
                                communicating_files, downloaded_files, graphs, referrer_files,
                                resolutions, siblings, subdomains, urls

                                For further details, see:
                                https://developers.virustotal.com/v3.0/reference#domains-relationships

            limit (str, optional): Limit of results to return
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the relationship object.
        """
        try:
            params = {'limit': limit, 'cursor': cursor}
            response = requests.get(self.base_url + '/{}/{}'.format(domain, relationship),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)


class IP:
    """Class for the IP Addresses endpoints
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the IP class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary containing proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/ip_addresses'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

        if api_key is None:
            raise Exception("You must provide a valid API key")

    def info_ip(self, ip, timeout=None):
        """Retrieve information for a given IP address, such as AS owner, country, reputation, etc.

        Parameters:
            ip (str): IPv4 address
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing the scan results.
        """
        try:
            response = requests.get(self.base_url + '/{}'.format(ip),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)
                                    
            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_votes(self, ip, limit=None, cursor=None, timeout=None):
        """Retrieve votes for a given IP address

        Parameters:
            ip (str): IPv4 address
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing the votes. The votes are located in the 'value' key.
        """
        params = {'limit': limit, 'cursor': cursor}
        try:
            response = requests.get(self.base_url + '/{}/votes'.format(ip),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()
        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def add_vote(self, ip, verdict, timeout=None):
        """Adds a verdict (vote) to a file. The verdict can be either 'malicious' or 'harmless'.

        Parameters:
            ip (str): IPv4 address
            verdict (str): 'malicious' (-1) or 'harmless' (+1)
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict containing the submitted vote.
        """
        verdicts = ['malicious', 'harmless']

        if verdict not in verdicts:
            raise Exception('Verdict must be harmless or malicious')

        data = {
            'data': {
                'type': 'vote',
                'attributes': {
                    'verdict': verdict
                }
            }
        }
        try:
            response = requests.post(self.base_url + '/{}/votes'.format(ip),
                                     headers=self.headers,
                                     data=json.dumps(data),
                                     proxies=self.proxies,
                                     timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_relationship(self, ip, relationship, limit=None, cursor=None, timeout=None):
        """Retrieve information on a user for a given ip identifier.

        Parameters:
            ip (str): IPv4 address
            relationship (str): Relationship object to retrieve. Can be one of the following:
                                communicating_files, downloaded_files, graphs, referrer_files,
                                resolutions, siblings, subips, urls

                                For further details, see:
                                https://developers.virustotal.com/v3.0/reference#ips-relationships

            limit (str, optional): Limit of results to return
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the relationship object.
        """
        try:
            params = {'limit': limit, 'cursor': cursor}
            response = requests.get(self.base_url + '/{}/{}'.format(ip, relationship),
                                    headers=self.headers,
                                    params=params,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)
