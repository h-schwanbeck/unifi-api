import sys
import json
import logging
from requests import Session, HTTPError
from time import time, sleep

PYTHON_VERSION = sys.version_info[0]

logging.basicConfig()
log = logging.getLogger(__name__)


class APIError(Exception):
    pass


class Controller:

    """Interact with a UniFi controller.

    Uses the JSON interface on port 8443 (HTTPS) to communicate with a UniFi
    controller. Operations will raise unifi.controller.APIError on obvious
    problems (such as login failure), but many errors (such as disconnecting a
    nonexistant client) will go unreported.

    >>> from unifi.controller import Controller
    >>> c = Controller('192.168.1.99', 'admin', 'p4ssw0rd')
    >>> for ap in c.get_aps():
    ...     print 'AP named %s with MAC %s' % (ap['name'], ap['mac'])
    ...
    AP named Study with MAC dc:9f:db:1a:59:07
    AP named Living Room with MAC dc:9f:db:1a:59:08
    AP named Garage with MAC dc:9f:db:1a:59:0b

    """

    def __init__(self, host, username, password, port=8443, version='v2', site_id='default', verify_ssl=False):
        """Create a Controller object.

        Arguments:
            host     -- the address of the controller host; IP or name
            username -- the username to log in with
            password -- the password to log in with
            port     -- the port of the controller host
            version  -- the base version of the controller API [v2|v3|v4]
            site_id  -- the site ID to connect to (UniFi >= 3.x)

        """

        self.host = host
        self.port = port
        self.version = version
        self.username = username
        self.password = password
        self.site_id = site_id
        self.url = 'https://' + self.host + ':' + str(self.port) + '/'
        self.api_url = self.url + self._construct_api_path()

        log.debug('Controller for %s', self.url)

        self.session = Session()
        self.session.verify = verify_ssl

        self._login()

    def _jsondec(self, resp):
        obj = resp.json()
        if 'meta' in obj:
            if obj['meta']['rc'] != 'ok':
                raise APIError(obj['meta']['msg'])
        if 'data' in obj:
            return obj['data']
        return obj

    def _read(self, url, params=None):
        process         = 1
        backofftime     = 1
        trial           = 1
        max_trials      = 5
        while(process and trial < max_trials):
            try:
                res = self.session.post(url, json=params)
                res.raise_for_status()
            except HTTPError as e:
                log.error('HTTP error: %s'%e)
                sleep(backofftime)
                backofftime = backofftime * 2
                trial = trial + 1
            else:
                process = 0                    
        return self._jsondec(res)

    def _construct_api_path(self, site_id=None):
        """Returns valid base API path

           The base API path for the URL is different depending on UniFi server version.
           Default returns correct path for latest known stable working versions.

        """
        if not site_id:
            site_id = self.site_id

        V2_PATH = 'api/'
        V3_PATH = 'api/s/' + site_id + '/'

        if(self.version == 'v2'):
            return V2_PATH
        if(self.version == 'v3'):
            return V3_PATH
        if(self.version == 'v4'):
            return V3_PATH
        else:
            return V2_PATH

    def _login(self):
        log.debug('login() as %s', self.username)
        
        if(self.version == 'v4'):
            params = {
                'username': self.username,
                'password': self.password
            }
            process         = 1
            backofftime     = 1
            trial           = 1
            max_trials      = 5
            while(process and trial < max_trials):
                try:
                    self.session.post(self.url + 'api/login', json=params).raise_for_status()
                except HTTPError as e:
                    log.error('URL error while trying connect to %s'%self.url)
                    sleep(backofftime)
                    backofftime = backofftime * 2
                    trial = trial + 1
                else:
                    process = 0                     
        else:
            params = {
                'login': 'login',
                'username': self.username,
                'password': self.password
            }
            process         = 1
            backofftime     = 1
            trial           = 1
            max_trials      = 5
            while ( process and trial < max_trials) :            
                try:      
                    self.session.get(self.url + 'login', params=params).raise_for_status()
                except HTTPError as e:
                    log.error('HTTP error: %s'%e)
                    sleep(backofftime)
                    backofftime = backofftime * 2
                    trial = trial + 1
                else:
                    process = 0

    def _logout(self):
        log.debug('logout()')
        process         = 1
        backofftime     = 1
        trial           = 1
        max_trials      = 5
        while ( process and trial < max_trials) :            
            try:
                self.session.get(self.url + 'logout', params=params).raise_for_status()
            except HTTPError as e:
                log.error('HTTP error: %s'%e)
                sleep(backofftime)
                backofftime = backofftime * 2
                trial = trial + 1
            else:
                process = 0

    def get_alerts(self):
        """Return a list of all Alerts."""

        return self._read(self.api_url + 'list/alarm')

    def get_alerts_unarchived(self):
        """Return a list of Alerts unarchived."""

        params = {'_sort': '-time', 'archived': False}
        return self._read(self.api_url + 'list/alarm', params)

    def get_statistics_last_24h(self):
        """Returns statistical data of the last 24h"""

        return self.get_statistics_24h(time())

    def get_statistics_24h(self, endtime):
        """Return statistical data last 24h from time"""

        params = {
            'attrs': ["bytes", "num_sta", "time"],
            'start': int(endtime - 86400) * 1000,
            'end': int(endtime - 3600) * 1000
        }
        return self._read(self.api_url + 'stat/report/hourly.system', params)

    def get_events(self):
        """Return a list of all Events."""

        return self._read(self.api_url + 'stat/event')

    def get_aps(self,site_id=None):
        """Return a list of all AP:s, with significant information about each."""

        if not site_id:
            site_id = self.site_id
        api_url = self.url + self._construct_api_path(site_id)
        params = {'_depth': 2, 'test': 0}
        return self._read(api_url + 'stat/device', params)

    def get_clients(self):
        """Return a list of all active clients, with significant information about each."""

        return self._read(self.api_url + 'stat/sta')

    def get_users(self):
        """Return a list of all known clients, with significant information about each."""

        return self._read(self.api_url + 'list/user')

    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""

        return self._read(self.api_url + 'list/usergroup')

    def get_wlan_conf(self):
        """Return a list of configured WLANs with their configuration parameters."""

        return self._read(self.api_url + 'list/wlanconf')

    def _run_command(self, command, params={}, mgr='stamgr', site_id=None):
        if not site_id:
            site_id = self.site_id
        api_url = self.url + self._construct_api_path(site_id)
        log.debug('_run_command(%s)', command)
        params.update({'cmd': command})
        return self._read(api_url + 'cmd/' + mgr, {'json': json.dumps(params)})

    def _mac_cmd(self, target_mac, command, mgr='stamgr'):
        log.debug('_mac_cmd(%s, %s)', target_mac, command)
        params = {'mac': target_mac, 'cmd': command}
        self._read(self.api_url + 'cmd/' + mgr, params)

    def block_client(self, mac):
        """Add a client to the block list.

        Arguments:
            mac -- the MAC address of the client to block.

        """

        self._mac_cmd(mac, 'block-sta')

    def unblock_client(self, mac):
        """Remove a client from the block list.

        Arguments:
            mac -- the MAC address of the client to unblock.

        """

        self._mac_cmd(mac, 'unblock-sta')

    def disconnect_client(self, mac):
        """Disconnect a client.

        Disconnects a client, forcing them to reassociate. Useful when the
        connection is of bad quality to force a rescan.

        Arguments:
            mac -- the MAC address of the client to disconnect.

        """

        self._mac_cmd(mac, 'kick-sta')
        
    def add_admin(self, email, name, role):
        """Adds a new admin.

        Arguments:
            email -- email address for admin.
            name -- username for admin,  no spaces,  can be changed
            role -- must be admin or readonly

        """
        params = {'email': email, 'name': name, 'role': role, 'for_sso':'false'}
        self._run_command('invide-admin', params, 'sitemgr')

    def revoke_admin(self, admin):
        """Revoke admin account. per site.

        Arguements:
            admin -- id of admin to revoke
        
        """

        params = {'admin': admin}
        self._run_command('revoke-admin', params, 'sitemgr')
    
    def restart_ap(self, mac):
        """Restart an access point (by MAC).

        Arguments:
            mac -- the MAC address of the AP to restart.

        """

        self._mac_cmd(mac, 'restart', 'devmgr')

    def restart_ap_name(self, name):
        """Restart an access point (by name).

        Arguments:
            name -- the name address of the AP to restart.

        """

        if not name:
            raise APIError('%s is not a valid name' % str(name))
        for ap in self.get_aps():
            if ap.get('state', 0) == 1 and ap.get('name', None) == name:
                self.restart_ap(ap['mac'])

    def archive_all_alerts(self):
        """Archive all Alerts
        """
        js = json.dumps({'cmd': 'archive-all-alarms'})
        params = {'json': js}
        answer = self._read(self.api_url + 'cmd/evtmgr', params)
        
    def create_backup(self):
        """Ask controller to create a backup archive file, response contains the path to the backup file.

        Warning: This process puts significant load on the controller may
                 render it partially unresponsive for other requests.
        """

        js = json.dumps({'cmd': 'backup'})
        params = {'json': js}
        answer = self._read(self.api_url + 'cmd/system', params)

        return answer[0].get('url')

    def get_backup(self, target_file='unifi-backup.unf'):
        """Get a backup archive from a controller.

        Arguments:
            target_file -- Filename or full path to download the backup archive to, should have .unf extension for restore.

        """
        download_path = self.create_backup()

        opener = self.opener.open(self.url + download_path)
        unifi_archive = opener.read()

        backupfile = open(target_file, 'w')
        backupfile.write(unifi_archive)
        backupfile.close()
