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


    def _construct_api_path(self):
        """Returns valid base API path

           The base API path for the URL is different depending on UniFi server version.
           Default returns correct path for latest known stable working versions.

        """

        if self.version in ['v3', 'v4']:
            return 'api/s/' + self.site_id + '/'
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


    def adopt_ap(self, ap_mac):
        """Adopt a new AP.

        Arguments:
            ap_mac -- MAC address of the given ap.

        """

        log.debug('_devmgr_cmd(%s, %s)', ap_mac, "adopt")
        params = {'cmd': 'adopt', 'mac': ap_mac}
        self._exec('cmd/devmgr', params)    


    def check_ap_state(self, ap_mac):
        """Check the status of a given AP in the site
        Arguments:
            ap_mac -- MAC address of the given ap.

        """
    
        return self._read('stat/device/%s'%ap_mac)


    def move_ap(self, ap_mac, site_id):
        """Move the specified AP from this site to another.

        Arguments:
            ap_mac -- MAC address of the given ap.
            site_id -- _id used by unifi for representing wifi site

        """

        log.debug('_sitemgr_cmd(%s, %s, %s)', ap_mac, site_id, "move-device")
        params = {'cmd': 'move-device', 'mac': ap_mac, 'site': site_id}
        self._exec('cmd/sitemgr', params)  


    def forget_ap(self, ap_mac):
        """Forget the specified AP from controller

        Arguments:
            ap_mac  -- MAC address of the given ap.
            site_id -- unifi site ID to which it should be moved

        """

        log.debug('_sitemgr_cmd(%s, %s, %s)', ap_mac, "delete-device")
        params = {'cmd': 'delete-device', 'mac': ap_mac}
        self._exec('cmd/sitemgr', params)


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


    def add_site(self, sitename):
        """Add a new site.

        Arguments:
            sitename -- namegiven for the new site.

        """

        log.debug('_sitemgr_cmd(%s, %s)', sitename, 'add-site')
        params = {'cmd': 'add-site', 'desc': sitename}
        self._exec('cmd/sitemgr', params)


 






    ''' Not converted yet




    def _set_setting(self,site_id, params={}, category='super_smtp'):

        api_url = self.url + self._construct_api_path(self.version,site_id=site_id)
        log.debug('_set_setting(%s)', category)
        if PYTHON_VERSION == 2:
            return self._read(api_url + 'set/setting/' + category, urllib.urlencode({'json': json.dumps(params)}))
        elif PYTHON_VERSION == 3:
            return self._read(api_url + 'set/setting/' + category, urllib.parse.urlencode({'json': json.dumps(params)}))        

    def set_smtp(self,site_id,host='127.0.0.1',port='25',use_ssl=False,
            use_auth=False,username=None,x_password=None,use_sender=False,sender=None):

        """Set SMTP seetings for this site

        Arguments:


        """
        log.debug('setting SMTP settings for site:%s',self.site_id )
        params = {'host': host,'port':port,'use_ssl':use_ssl,
                   'use_auth':use_auth,'username':username,'x_password':x_password,'use_sender':use_sender,'sender':sender}
        return self._set_setting(site_id=site_id,params=params, category='super_smtp')          

    def create_site_admin(self,site_id,name,email):
        """Create Admin for the particular site

        Arguments:
            name -- Admin User Name.
            email -- Email
            site_id --  unifi site ID to which it should be moved

        """
        log.debug('_sitemgr_cmd(%s, %s, %s)', name,site_id, "invite-admin")
        params = {'name': name,'email':email,'site':site_id}
        return self._run_command('invite-admin', params, mgr='sitemgr',site_id=site_id)  

    def set_guest_access(self,site_id,site_code,portal_ip,portal_subnet,portal_hostname):

        """Set SMTP seetings for this site

        Arguments:


        """
        log.debug('setting Guest settings for site:%s',site_id )

        params =  {"portal_enabled":True,"auth":"custom","x_password":"","expire":"480","redirect_enabled":False,"redirect_url":'',
        "custom_ip":portal_ip,"portal_customized":False,"portal_use_hostname":True,"portal_hostname":
        portal_hostname,"voucher_enabled":False,"payment_enabled":False,"gateway":"paypal","x_paypal_username":
        "","x_paypal_password":"","x_paypal_signature":"","paypal_use_sandbox":False,"x_stripe_api_key":"","x_quickpay_merchantid":
        "","x_quickpay_md5secret":"","x_authorize_loginid":"","x_authorize_transactionkey":"","authorize_use_sandbox":
        False,"x_merchantwarrior_merchantuuid":"","x_merchantwarrior_apikey":"","x_merchantwarrior_apipassphrase":
        "","merchantwarrior_use_sandbox":False,"x_ippay_terminalid":"","ippay_use_sandbox":False,"restricted_subnet_1":
        "192.168.0.0/16","restricted_subnet_2":"172.16.0.0/12","restricted_subnet_3":"10.0.0.0/8","allowed_subnet_1":
        portal_subnet,"key":"guest_access","site_id":site_code}  

        return self._set_setting(site_id=site_id,params=params, category='guest_access')   


'''
