# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Cloudbase-init
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.common.utils import data_utils
from tempest.common import debug
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest.scenario import utils as test_utils
from tempest.test import services
from tempest.common.utils.windows.remote_client import WinRemoteClient
import time
import tempfile

LOG = logging.getLogger("cbinit")

CONF = config.CONF

class AAA(object):
    def func(self):
        pass

class TestServices(manager.ScenarioTest):

    @classmethod
    def check_preconditions(cls):
        # super(TestServices, cls).check_preconditions()
        cfg = CONF.network
        if not (cfg.tenant_networks_reachable or cfg.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

    @classmethod
    def create_test_server(cls, **kwargs):
        """Wrapper utility that returns a test server."""
        name = data_utils.rand_name(cls.__name__ + "-instance")
        if 'name' in kwargs:
            name = kwargs.pop('name')
        flavor = CONF.compute.flavor_ref
        image_id = CONF.compute.image_ref

        resp, body = cls.servers_client.create_server(
            name, image_id, flavor, **kwargs)

        # handle the case of multiple servers
        servers = [body]
        if 'min_count' in kwargs or 'max_count' in kwargs:
            # Get servers created which name match with name param.
            r, b = cls.servers_client.list_servers()
            servers = [s for s in b['servers'] if s['name'].startswith(name)]

        if 'wait_until' in kwargs:
            for server in servers:
                try:
                    cls.servers_client.wait_for_server_status(
                        server['id'], kwargs['wait_until'])
                    cls.instance = server
                except Exception as ex:
                    if ('preserve_server_on_error' not in kwargs
                        or kwargs['preserve_server_on_error'] is False):
                        for server in servers:
                            try:
                                cls.servers_client.delete_server(server['id'])
                            except Exception:
                                pass
                    raise ex

        cls.servers.extend(servers)

        return resp, body

    @classmethod
    def setUpClass(cls):
        super(TestServices, cls).setUpClass()

        cls.check_preconditions()
        cls.keypairs = {}
        cls.subnets = []
        cls.routers = []
        cls.servers = []
        cls.floating_ips = {}
        cls.default_ci_username = 'CiAdmin'
        cls.default_ci_password = 'Passw0rd'

        cls.create_test_server(wait_until='ACTIVE')
        cls._assign_floating_ip()

    @classmethod
    def tearDownClass(cls):
        cls.servers_client.delete_server(cls.instance['id'])
        cls.servers_client.wait_for_server_termination(cls.instance['id'])
        cls.floating_ips_client.delete_floating_ip(cls.floating_ip['id'])
        super(TestServices, cls).tearDownClass()

    def setUp(self):
        super(TestServices, self).setUp()
        # Setup image and flavor the test instance
        # Support both configured and injected values
        if not hasattr(self, 'image_ref'):
            self.image_ref = CONF.compute.image_ref
        if not hasattr(self, 'flavor_ref'):
            self.flavor_ref = CONF.compute.flavor_ref
        self.image_utils = test_utils.ImageUtils()
        if not self.image_utils.is_flavor_enough(self.flavor_ref,
                                                 self.image_ref):
            raise self.skipException(
                '{image} does not fit in {flavor}'.format(
                    image=self.image_ref, flavor=self.flavor_ref
                )
            )
        self.keypair = self.create_keypair()
        self.security_group = self._create_security_group()
        self.get_private_network()

        self.host_name = ""
        self.instance_name = ""

    def get_private_network(self):
        networks = self.networks_client.list_networks()[1]
        for network in networks:
            if network['label'] == 'private_cbinit':
                self.private_network = network

    @classmethod
    def _assign_floating_ip(self):
        # Obtain a floating IP
        _, self.floating_ip = self.floating_ips_client.create_floating_ip()

        self.floating_ips_client.associate_floating_ip_to_server(
            self.floating_ip['ip'], self.instance['id'])

    # TODO: do it with a flag to replace the code or not
    def _first_login(self, ip_address):
        wait_cmd = 'powershell "(Get-WmiObject Win32_Account | where -Property Name -contains CiAdmin).FullName"'
        #wait for boot completion
        wsmancmd = WinRemoteClient(ip_address, self.default_ci_username,
                                   self.default_ci_password)
        while True:
            try:
                std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(wait_cmd)
                if std_err:
                    time.sleep(5)
                elif std_out == 'CiAdmin\r\n':
                    break
            except:
                time.sleep(5)

        #install cbinit
        cmd1 = "powershell Invoke-webrequest -uri 'https://raw.githubusercontent.com/trobert2/windows-openstack-imaging-tools/master/installCBinit.ps1' -outfile 'C:\\\\installcbinit.ps1'"
        cmd2 = 'powershell "C:\\\\installcbinit.ps1"'

        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd1)
        LOG.info("downloading for cbinit: "+str(std_out))
        LOG.info("downloading for cbinit: "+str(std_err))

        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd2)
        LOG.info("installing cbinit: "+str(std_out))
        LOG.info("installing cbinit: "+str(std_err))

        #check cbinit complete
        svr = self.instance
        key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` Solutions\\Cloudbase-init\\' + svr.id + '\\Plugins'
        wait_cmd = 'powershell (Get-Item %s).ValueCount' % key

        while True:
            try:
                std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(wait_cmd)
                if std_err:
                    time.sleep(5)
                elif int(std_out) >= 10:
                    break
            except:
                time.sleep(5)

    def _check_services(self):
        # The target login is assumed to have been configured for
        # key-based authentication by cloud-init.
        try:
            for server, floating_ips in self.floating_ips.iteritems():
                for floating_ip in floating_ips:
                    ip_address = floating_ip.floating_ip_address
                    self._first_login(ip_address)
                    self._test_services(ip_address)
                    self._test_service_keys(ip_address)
                    self._test_disk_expanded(ip_address)
                    self._test_username_created(ip_address)
                    self._test_hostname_set(ip_address)
                    # self._test_ntp_service_running(ip_address)

        except Exception as exc:
            LOG.exception(exc)
            debug.log_ip_ns()
            raise exc

    def _get_password(self, server_id):
        temp_key_file = tempfile.NamedTemporaryFile(mode='w+r', delete=False)
        temp_key_file.write(self.keypairs[self.tenant_id].private_key)
        temp_key_file.close()
        password = ''
        while password == '':
            # password = self.compute_client.servers.get_password(
            #     server_id, temp_key_file.name)
            password = self.servers_client.get_password(server_id)
        return password
        # os.remove(temp_key_file.name)

    def _test_service_keys(self, pub_ip):
        svr = self.instance
        key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` Solutions\\Cloudbase-init\\' + svr.id + '\\Plugins'
        cmd = 'powershell (Get-Item %s).ValueCount' % key
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        self.assertEqual(int(std_out), 11)

    def _test_services(self, pub_ip):
        username = 'Administrator'
        # TODO:Do it clean, with the right server, not first
        #but i will spawn one server per tenant creation I guess.....
        svr = self.instance

        cmd = 'powershell (Get-Service "| where -Property Name -match cloudbase-init").DisplayName'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Cloud Initialization Service\r\n")

    def _test_disk_expanded(self, pub_ip):
        svr = self.instance
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        # TODO: get the right image, not the first one
        image = self.instance
        image_size = image._info['OS-EXT-IMG-SIZE:size']
        cmd = 'powershell (Get-WmiObject "win32_logicaldisk | where -Property DeviceID -Match C:").Size'
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        self.assertTrue(int(std_out) > image_size)

    def _test_username_created(self, pub_ip):
        svr = self.instance
        cmd = 'powershell "Get-WmiObject Win32_Account | where -Property Name -contains Admin"'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)

        self.assertIsNotNone(std_out)

    def _test_hostname_set(self, pub_ip):
        svr = self.instance
        cmd = 'powershell (Get-WmiObject "Win32_ComputerSystem").Name'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out).lower(), str(svr.name[:15]).lower() + '\r\n')

    def _test_ntp_service_running(self, pub_ip):
        svr = self.instance
        cmd = 'powershell (Get-Service "| where -Property Name -match W32Time").Status'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Running\r\n")

    # TODO(trobert): redo
    # def _check_userdata(self):
    #     svr = self.instance
    #     cmd = 'powershell (Get-Item "~\\Documents\\*.txt").length'
    #
    #     ip_address = floating_ip.floating_ip_address
    #     wsmancmd = WinRemoteClient(ip_address,
    #                                self.default_ci_username,
    #                                self.default_ci_password)
    #     std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
    #     LOG.debug(str(std_out))
    #     LOG.debug(std_err)
    #     self.assertEqual(str(std_out), str(3))

    @services('compute', 'network')
    def test_userdata_mime_type(self):
        pass
        # self._check_userdata()

    @services('compute', 'network')
    def test_userdata_mime_type1(self):
        pass

        # self.assertEqual(0,1)
        # self._check_userdata()

    @services('compute', 'network')
    def test_userdata_mime_type2(self):
        pass

        # self._check_userdata()

# NETID1=`neutron net-create cbinit_private --provider:network_type flat --provider:physical_network physnet1 | awk '{if (NR == 6) {print $4}}'`
# SUBNETID1=`$neutron subnet-create cbinit_private 11.12.13.0/24 --dns_nameservers list=true 8.8.8.8 | awk '{if (NR == 11) {print $4}}'`
