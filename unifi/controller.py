import logging
from requests import Session, HTTPError
from time import time, sleep

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
            host       -- the address of the controller host; IP or name
            username   -- the username to log in with
            password   -- the password to log in with
            port       -- the port of the controller host
            version    -- the base version of the controller API [v2|v3|v4]
            site_id    -- the site ID to connect to (UniFi >= 3.x)
            verify_ssl -- set True if controller has a valid SSL cert installed

        """

        self.host = host
        self.port = port
        self.version = version
        self.username = username
        self.password = password
        self.site_id = site_id
        self.base_url = "https://{host}:{port}/".format(host=self.host, port=self.port)
        self.api_url = "{url}{path}".format(url=self.base_url, path=self._construct_api_path())

        log.debug('Controller for %s', self.base_url)

        self.session = Session()
        self.session.verify = verify_ssl
        self.max_retry = 3

        self._login()


    def _jsondec(self, resp):
        try:
            obj = resp.json()
            if 'meta' in obj:
                if obj['meta']['rc'] != 'ok':
                    raise APIError(obj['meta']['msg'])
            if 'data' in obj:
                return obj['data']
            return obj
        except:
            return None


    def _raw(self, url, params=None):
        trial = 0
        while(trial < self.max_retry):
            try:
                res = self.session.post(url, json=params)
                res.raise_for_status()
            except HTTPError as e:
                log.error('HTTP error: %s', e)
                sleep(2**trial)
                trial += 1
            else:
                break
        return res


    def _read(self, command, params=None):
        res = self._raw(self.api_url + command, params)
        return self._jsondec(res)


    def _exec(self, command, params=None):
        self._raw(self.api_url + command, params)


    def _construct_api_path(self, site_id=None):
        """Returns valid base API path

           The base API path for the URL is different depending on UniFi server version.
           Default returns correct path for latest known stable working versions.

        """

        if not site_id:
            site_id = self.site_id

        if self.version in ['v3', 'v4']:
            return 'api/s/' + site_id + '/'
        else:
            return 'api/'


    def _login(self):
        log.debug('login() as %s', self.username)

        params = {
            'username': self.username,
            'password': self.password
        }

        if self.version in ['v4']:
            login_url = self.base_url + 'api/login'
        else:
            params.update({'login': 'login'})
            login_url = self.base_url + 'login'

        self._raw(login_url, params)


    def _logout(self):
        log.debug('logout()')
        logout_url = 'logout'
        if self.version in ['v4']:
            logout_url = 'api/logout'
        self._raw(self.base_url + logout_url)


    def get_alerts(self):
        """Return a list of all Alerts."""

        return self._read('list/alarm')


    def get_alerts_unarchived(self):
        """Return a list of Alerts unarchived."""

        params = {'_sort': '-time', 'archived': False}
        return self._read('list/alarm', params)


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
        return self._read('stat/report/hourly.system', params)


    def get_events(self):
        """Return a list of all Events."""

        return self._read('stat/event')


    def get_aps(self):
        """Return a list of all AP:s, with significant information about each."""

        params = {'_depth': 2, 'test': 0}
        return self._read('stat/device', params)


    def get_clients(self):
        """Return a list of all active clients, with significant information about each."""

        return self._read('stat/sta')


    def get_users(self):
        """Return a list of all known clients, with significant information about each."""

        return self._read('list/user')


    def get_user_groups(self):
        """Return a list of user groups with its rate limiting settings."""

        return self._read('list/usergroup')


    def get_wlan_conf(self):
        """Return a list of configured WLANs with their configuration parameters."""

        return self._read('list/wlanconf')


    def block_client(self, mac):
        """Add a client to the block list.

        Arguments:
            mac -- the MAC address of the client to block.

        """

        params = {'cmd': 'block-sta', 'mac': mac}
        self._exec('cmd/stamgr', params)


    def unblock_client(self, mac):
        """Remove a client from the block list.

        Arguments:
            mac -- the MAC address of the client to unblock.

        """

        params = {'cmd': 'unblock-sta', 'mac': mac}
        self._exec('cmd/stamgr', params)


    def disconnect_client(self, mac):
        """Disconnect a client.

        Disconnects a client, forcing them to reassociate. Useful when the
        connection is of bad quality to force a rescan.

        Arguments:
            mac -- the MAC address of the client to disconnect.

        """

        params = {'cmd': 'kick-sta', 'mac': mac}
        self._exec('cmd/stamgr', params)


    def add_admin(self, email, name, role):
        """Adds a new admin.

        Arguments:
            email   -- email address for admin.
            name    -- username for admin,  no spaces,  can be changed
            role    -- must be admin or readonly

        """

        params = {
            'email'  : email,
            'name'   : name,
            'role'   : role,
            'for_sso': 'false'
            'cmd'    : 'invite-admin'
        }
        self._exec('cmd/sitemgr', params)


    def revoke_admin(self, admin):
        """Revoke admin account. per site.

        Arguements:
            admin -- id of admin to revoke

        """

        params = {'admin': admin, 'cmd': 'revoke-admin'}
        self._exec(api_url, params)


    def restart_ap(self, mac):
        """Restart an access point (by MAC).

        Arguments:
            mac -- the MAC address of the AP to restart.

        """

        params = {'cmd': 'restart', 'mac': mac}
        self._exec('cmd/devmgr', params)


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

        params = {'cmd': 'archive-all-alarms'}
        self._exec('cmd/evtmgr', params)


    def _create_backup(self):
        """Ask controller to create a backup archive file, response contains the path to the backup file.

        Warning: This process puts significant load on the controller may
                 render it partially unresponsive for other requests.
        """

        params = {'cmd': 'backup'}
        answer = self._read(self.api_url + 'cmd/system', params)

        return answer[0].get('url')


    def get_backup(self, target_file='unifi-backup.unf'):
        """Get a backup archive from a controller.

        Arguments:
            target_file -- Filename or full path to download the backup archive to, should have .unf extension for restore.

        """
        download_path = self._create_backup()

        with open(target_file, 'wb') as handle:
            response = self.session.get(download_path, stream=True)

            for block in response.iter_content(1024):
                handle.write(block)

