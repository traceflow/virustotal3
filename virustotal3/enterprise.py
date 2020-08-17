""" VirusTotal API v3 Enterprise

Module to interact with the Enterprise part of the API.
"""
import os
import bz2
import json
import requests
import virustotal3.errors

from io import BytesIO

VirusTotalApiError = virustotal3.errors.VirusTotalApiError

def _raise_exception(response):
    """Raise Exception

    Function to raise an exception using the error messages returned by the API.

    

    Parameters:
        response (dict) Reponse containing the error returned by the API.
    """
    # https://developers.virustotal.com/v3.0/reference#errors
    raise VirusTotalApiError(response.text)

def search(api_key, query, order=None, limit=None, cursor=None,
           descriptors_only=None, proxies=None, timeout=None):
    """Search for files and return the file details.

    Parameters:
        api_key (str): VirusTotal API key
        query (str): Search query
        order (str, optional): Sort order. Can be one of the following:
                     size, positives, last_submission_date, first_submission_date,
                     times_submitted. Can be followed by a + or -.
                     Default is 'last_submission_date-'
        limit (int, optional): Maximum number of results to retrieve
        cursor (str, optional): Continuation cursor
        descriptors_only (bool, optional): Return file descriptor only instead of all details
        proxies (dict, optional): Dictionary with proxies
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.

    Returns:
        A dict with the results from the search.
    """
    if api_key is None:
        raise Exception("You must provide a valid API key")

    try:
        params = {'query': query, 'order': order, 'limit': limit,
                  'cursor': cursor, 'descriptors_only': descriptors_only}
        response = requests.get('https://www.virustotal.com/api/v3/intelligence/search',
                                params=params,
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


def _get_feed(api_key, type_, time, timeout=None):
    """ Get a minute from a feed

    Parameters:
        api_key (str): VT key
        type_ (str): type of feed to get
        time (str): YYYYMMDDhhmm
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.
    
    Returns:
        StringIO: each line is a json string for one report
    """
    if api_key is None:
        raise Exception("You must provide a valid API key")

    try:
        response = requests.get('https://www.virustotal.com/api/v3/feeds/{}/{}'.format(type_, time),
                                headers={'x-apikey': api_key,
                                         'Accept': 'application/json'},
                                timeout=timeout)

        if response.status_code != 200:
            _raise_exception(response)

        return BytesIO(bz2.decompress(response.content))
    except requests.exceptions.RequestException as error:
        print(error)
        exit(1)


def file_feed(api_key, time, timeout=None):
    """Get a file feed batch for a given date, by the minute.

    From the official documentation:
    "Time 201912010802 will return the batch corresponding to December 1st, 2019 08:02 UTC.
    You can download batches up to 7 days old, and the most recent batch has always a 60 minutes
    lag with respect with to the current time."

    Parameters:
        api_key (str): VirusTotal key
        time (str): YYYYMMDDhhmm
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.
    
    Returns:
        StringIO: each line is a json string for one report
    """
    return _get_feed(api_key, "files", time, timeout=timeout)


def url_feed(api_key, time, timeout=None):
    """Get a URL feed batch for a given date, by the minute.

    From the official documentation:
    "Time 201912010802 will return the batch corresponding to December 1st, 2019 08:02 UTC.
    You can download batches up to 7 days old, and the most recent batch has always a 60 minutes
    lag with respect with to the current time."

    Parameters:
        api_key (str): VirusTotal key
        time (str): YYYYMMDDhhmm
        timeout (float, optional): The amount of time in seconds the request should wait before timing out.
    
    Returns:
        StringIO: each line is a json string for one report
    """
    return _get_feed(api_key, "urls", time, timeout=timeout)


class Livehunt:
    """VT Enterprise Livehunt Endpoints

    Livehunt endpoints allowing to manage YARA rules and notifications.

    Attributes:
        api_key (str): VirusTotal API key
        proxies (dict, optional): Dictionary with proxies
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Livehunt class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary with proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/intelligence'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

        if api_key is None:
            raise Exception("You must provide a valid API key")

    def get_rulesets(self, ruleset_id=None, limit=None, fltr=None, order=None, cursor=None, timeout=None):
        """Retrieve one or multiple rulesets

        Retrieve a single ruleset for a given ID or all rulesets at once.

        Parameters:
            ruleset_id (str, optional): Ruleset ID required to return a single specific ruleset
            limit (int, optional): Maximum number of rulesets to retrieve
            fltr (str, optional): Return the rulesets matching the given criteria only
            order (str, optional): Sort order
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with one or multiple rulesets.
        """
        try:
            if ruleset_id:
                params = {'id': ruleset_id}
                response = requests.get(self.base_url + '/hunting_rulesets/{}'.format(ruleset_id),
                                        headers=self.headers,
                                        params=params,
                                        proxies=self.proxies,
                                        timeout=timeout)
            else:
                params = {'limit': limit, 'filter': fltr, 'order': order, 'cursor': cursor}
                response = requests.get(self.base_url + '/hunting_rulesets',
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

    def create_rulset(self, data, timeout=None):
        """ Create a Livehunt ruleset

        Parameters:
            data (dict): Rule to create.
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.
        Returns:
            A dict with the created rule.
        """
        try:
            response = requests.post(self.base_url + '/hunting_rulesets',
                                     data=json.dumps(data),
                                     headers=self.headers,
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def update_ruleset(self, ruleset_id, data, timeout=None):
        """ Update existing ruleset

        Update an existing ruleset for a given ID

        Parameters:
            ruleset_id (str): Ruleset ID
            data (dict): Ruleset to update as dictionary. The package will take care of creating the JSON object.
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the updated rule.
        """
        try:
            response = requests.patch(self.base_url + '/hunting_rulesets/{}'.format(ruleset_id),
                                      data=json.dumps(data),
                                      headers=self.headers,
                                      proxies=self.proxies,
                                      timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def delete_ruleset(self, ruleset_id, timeout=None):
        """ Delete ruleset

        Delete ruleset for a given ID

        Parameters:
            ruleset_id (str): Ruleset ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            None
        """
        try:
            response = requests.delete(self.base_url + '/hunting_rulesets/{}'.format(ruleset_id),
                                       headers=self.headers,
                                       proxies=self.proxies,
                                       timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return None

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_notifications(self, notification_id=None, limit=None, fltr=None, cursor=None, timeout=None):
        """Retrieve a single notification for a given ID or all notifications at once.

        Parameters:
            notification_id (str, optional): Notification ID required to return a
                                             single specific ruleset.
            limit (int, optional): Maximum number of rulesets to retrieve
            fltr (str, optional): Return the rulesets matching the given criteria only
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with one or multiple notifications in JSON format.
        """
        try:
            if notification_id:
                params = {'id': notification_id}
                response = requests.get(self.base_url + \
                                        '/hunting_notifications/{}'.format(notification_id),
                                        headers=self.headers,
                                        proxies=self.proxies,
                                        params=params,
                                        timeout=timeout)
            else:
                params = {'limit': limit, 'filter': fltr, 'cursor': cursor}
                response = requests.get(self.base_url + '/hunting_notifications',
                                        headers=self.headers,
                                        proxies=self.proxies,
                                        params=params,
                                        timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def delete_notifications(self, tag, timeout=None):
        """Delete notifications for a given tag

        Parameters:
            tag (str): Notification tag
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            None
        """
        try:
            params = {'tag': tag}
            response = requests.delete(self.base_url + '/hunting_notifications',
                                       headers=self.headers,
                                       params=params,
                                       proxies=self.proxies,
                                       timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return None

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def delete_notification(self, notification_id, timeout=None):
        """Delete a notification for a given notification ID

        Parameters:
            notification_id (str): Notification ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            None
        """
        try:
            params = {'id': notification_id}
            response = requests.delete(self.base_url + '/hunting_notifications',
                                       headers=self.headers,
                                       params=params,
                                       proxies=self.proxies,
                                       timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return None

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_notification_files(self, limit=None, cursor=None, timeout=None):
        """Retrieve file details and context attributes from notifications.

        Parameters:
            limit (int, optional): Maximum number of rulesets to retrieve
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with one or multiple notifications.
        """
        try:
            params = {'limit': limit, 'cursor': cursor}
            response = requests.get(self.base_url + '/hunting_notification_files',
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


class Retrohunt:
    """VirusTotal Retrohunt class

    Run Retrohunting jobs.
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Retrohunt class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary with proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/intelligence'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

    def get_jobs(self, job_id=None, limit=None, fltr=None, cursor=None, timeout=None):
        """Retrieve an existing Retrohunt jobs. Returns all jobs if no ID is specified.

        Parameters:
            job_id (str, optional): Job ID
            limit (int, optional): Maximum number of jobs to retrieve
            fltr (str, optional): Filter matching specific jobs only
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with one of multiple jobs.
        """
        try:
            if job_id:
                params = {'id': job_id}
                response = requests.get(self.base_url + '/Retrohunt_jobs/{}'.format(job_id),
                                        headers=self.headers,
                                        params=params,
                                        proxies=self.proxies,
                                        timeout=timeout)
            else:
                params = {'limit': limit, 'filter': fltr, 'cursor': cursor}
                response = requests.get(self.base_url + '/Retrohunt_jobs',
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

    def create_job(self, data, timeout=None):
        """Create a new Retrohunt job

        Parameters:
            data (dict): Rule to create. See example below.

        Returns:
            A dict with the created rule.
        """
        try:
            response = requests.post(self.base_url + '/Retrohunt_jobs',
                                     data=json.dumps(data),
                                     headers=self.headers,
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def delete_job(self, job_id, timeout=None):
        """Delete a job for a given ID

        Parameters:
            job_id (str): Job ID

        Returns:
            None
        """
        try:
            response = requests.delete(self.base_url + '/Retrohunt_jobs/{}'.format(job_id),
                                       headers=self.headers,
                                       proxies=self.proxies,
                                       timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return None

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def abort_job(self, job_id, timeout=None):
        """Abort a job for a given ID

        Parameters:
            job_id (str): Job ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            None
        """
        try:
            response = requests.post(self.base_url + '/Retrohunt_jobs/{}/abort'.format(job_id),
                                     headers=self.headers,
                                     proxies=self.proxies,
                                     timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return None

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_matching_files(self, job_id, timeout=None):
        """Get matching files for a job ID

        Parameters:
            job_id (str): Job ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with matching files
        """
        try:
            response = requests.get(self.base_url + \
                                    '/Retrohunt_jobs/{}/matching_files'.format(job_id),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)


class Accounts:
    """VT Enterprise Users & Groups

    Manage and retrieve information on users and groups.

    This part of the API still is under development by VirusTotal.
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Retrohunt class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary with proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

    def info_user(self, user_id, timeout=None):
        """Retrieve information on a user for a given ID

        Parameters:
            user_id (str): User ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the details on the user.
        """
        try:
            params = {'id': user_id}
            response = requests.get(self.base_url + '/users/{}'.format(user_id),
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

    def info_group(self, group_id, timeout=None):
        """Retrieve information on a group for a given ID

        Parameters:
            group_id (str): User ID
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the details on the group.
        """
        try:
            response = requests.get(self.base_url + '/groups/{}'.format(group_id),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=None)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_relationship(self, group_id, relationship, limit=None, cursor=None, timeout=None):
        """Retrieve information on a user for a given group ID. Currently, the only relationship object supported by the
        VirusTotal v3 API is `graphs`.

        Parameters:
            group_id (str): User ID
            relationship (str): Relationship
            limit (str, optional): Limit of results to return
            cursor (str, optional): Continuation cursor
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the relationship object.
        """
        try:
            params = {'limit': limit, 'cursor': cursor}
            response = requests.get(self.base_url + \
                                    '/groups/{}/relationships/{}'.format(group_id, relationship),
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


class ZipFiles:
    """Zipping files

    Zip and download an individual file or multiple files. Zip files are password protected.

    This part of the API still is under development by VirusTotal.
    """

    def __init__(self, api_key=None, proxies=None):
        """
        Constructor for the Retrohunt class.

        Parameters:
            api_key (str): VirusTotal API key
            proxies (dict, optional): Dictionary with proxies
        """
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/api/v3/intelligence'
        self.headers = {'x-apikey': self.api_key,
                        'Accept': 'application/json'}
        self.proxies = proxies

    def create_zip(self, data, timeout=None):
        """Creates a password-protected ZIP file with files from VirusTotal.

        Parameters:
            data (str): Dictionary with a list of hashes to download. See example request for dictionary:
                        https://developers.virustotal.com/v3.0/reference#zip_files
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.
        Returns:
            A dict with the progression and status of the archive compression process, including its ID. Use the
            info_zip() function to check the status of a Zip file for a given ID.
        """
        try:
            response = requests.post(self.base_url + '/zip_files',
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

    def info_zip(self, zip_id, timeout=None):
        """Check the status of a Zip file for a given ID.

        Parameters:
            zip_id (str): ID of the zip file
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            A dict with the status of the zip file creation. When the value of the 'status' key is set to 'finished',
            the file is ready for download. Other status are: 'starting', 'creating', 'timeout', 'error-starting',
            'error-creating'.
        """
        try:
            response = requests.get(self.base_url + '/zip_files/{}'.format(zip_id),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)

            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_url(self, zip_id, timeout=None):
        """Get the download URL of a Zip file for a given ID. Will raise an exception if the file is not yet ready to
        download. Should be called only after info_zip() returns a 'finished' status.

        Parameters:
            zip_id (str): ID of the zip file
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.

        Returns:
            URL of the zip file to download
        """

        try:
            response = requests.get(self.base_url + '/zip_files/{}/download_url'.format(zip_id),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            return response.json()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)

    def get_zip(self, zip_id, output_dir, timeout=None):
        """Download a zip file for a given ID.

        Parameters:
            zip_id (str): ID of the zip file
            output_dir (str): Output directory where the file will be downloaded.
            timeout (float, optional): The amount of time in seconds the request should wait before timing out.
        """

        try:
            response = requests.get(self.base_url + '/zip_files/{}/download'.format(zip_id),
                                    headers=self.headers,
                                    proxies=self.proxies,
                                    timeout=timeout)
            if response.status_code != 200:
                _raise_exception(response)

            with open(output_dir + '{}.zip'.format(zip_id), 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()

        except requests.exceptions.RequestException as error:
            print(error)
            exit(1)
        except os.error as error:
            print(error)
            exit(1)
