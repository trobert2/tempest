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
import pdb

LOG = logging.getLogger("cbinit")

CONF = config.CONF


class TestServices(manager.ScenarioTest):
    first_login = True

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
        cls.keypairs = {}
        cls.security_groups = []
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
        # try:
        #     cls.servers_client.remove_security_group(
        #         cls.instance['id'], cls.security_group['name'])
        # except Exception as ex:
        #     LOG.info(ex)

        cls.servers_client.delete_server(cls.instance['id'])
        cls.servers_client.wait_for_server_termination(cls.instance['id'])
        cls.floating_ips_client.delete_floating_ip(cls.floating_ip['id'])

        super(TestServices, cls).tearDownClass()

    def change_security_group(self, server_id):
        security_group = self._create_security_group()
        self.security_groups.append(security_group)

        for sec_group in self.instance['security_groups']:
            try:
                self.servers_client.remove_security_group(server_id,
                                                          sec_group['name'])
            except Exception as ex:
                LOG.info(ex)

        self.servers_client.add_security_group(server_id,
                                               security_group['name'])

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
        self.change_security_group(self.instance['id'])

        self.private_network = self.get_private_network()

        self.host_name = ""
        self.instance_name = ""
        self.remote_client = WinRemoteClient(self.floating_ip['ip'],
                                             self.default_ci_username,
                                             self.default_ci_password)
        self._first_login(self.remote_client)

    def tearDown(self):
        for sec_group in self.security_groups:
            print sec_group
            try:
                self.servers_client.remove_security_group(
                    self.instance['id'], sec_group['name'])
            except Exception as ex:
                LOG.info(ex)

        super(TestServices, self).tearDown()

    def get_private_network(self):
        networks = self.networks_client.list_networks()[1]
        for network in networks:
            if network['label'] == 'private_cbinit':
                return network

    @classmethod
    def _assign_floating_ip(self):
        # Obtain a floating IP
        _, self.floating_ip = self.floating_ips_client.create_floating_ip()

        self.floating_ips_client.associate_floating_ip_to_server(
            self.floating_ip['ip'], self.instance['id'])

    # TODO: do it with a flag to replace the code or not
    def _first_login(self, remote_client):
        if TestServices.first_login:
            TestServices.first_login = False

            wait_cmd = 'powershell "(Get-WmiObject Win32_Account | where -Property Name -contains CiAdmin).FullName"'
            #wait for boot completion
            wsmancmd = remote_client

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
            LOG.info("downloading for cbinit: " + str(std_out))
            LOG.info("downloading for cbinit: " + str(std_err))

            std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd2)
            LOG.info("installing cbinit: " + str(std_out))
            LOG.info("installing cbinit: " + str(std_err))

            key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` ' \
                  'Solutions\\Cloudbase-init\\' + self.instance['id'] + '\\Plugins'
            wait_cmd = 'powershell (Get-Item %s).ValueCount' % key

            self.servers_client.wait_for_server_status(
                server_id=self.instance['id'], status='SHUTOFF',
                extra_timeout=600)

            self.servers_client.start(self.instance['id'])

            self.servers_client.wait_for_server_status(
                server_id=self.instance['id'], status='ACTIVE')
            #set so it does not execute before every test

            while True:
                try:
                    std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(wait_cmd)
                    if std_err:
                        time.sleep(5)
                    elif int(std_out) >= 10:
                        break
                except:
                    time.sleep(5)

    def _get_password(self, server_id):
        temp_key_file = tempfile.NamedTemporaryFile(mode='w+r', delete=False)
        temp_key_file.write(self.keypairs[self.tenant_id].private_key)
        temp_key_file.close()
        password = ''
        while password == '':
            password = self.servers_client.get_password(server_id)
        return password

    def test_service_keys(self):
        key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` Solutions\\Cloudbase-init\\' + self.instance['id'] + '\\Plugins'
        cmd = 'powershell (Get-Item %s).ValueCount' % key
        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        self.assertEqual(int(std_out), 13)

    def test_service(self):
        cmd = 'powershell (Get-Service "| where -Property Name -match cloudbase-init").DisplayName'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Cloud Initialization Service\r\n")

    def test_disk_expanded(self):
        # TODO: get the right image, not the first one
        image = self.images_client.get_image(CONF.compute.image_ref)
        image_size = image[1]['OS-EXT-IMG-SIZE:size']
        cmd = 'powershell (Get-WmiObject "win32_logicaldisk | where -Property DeviceID -Match C:").Size'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        self.assertTrue(int(std_out) > image_size)

    def test_username_created(self):
        cmd = 'powershell "Get-WmiObject Win32_Account | '
        cmd += 'where -Property Name -contains Admin"'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)

        self.assertIsNotNone(std_out)

    def test_hostname_set(self):
        cmd = 'powershell (Get-WmiObject "Win32_ComputerSystem").Name'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        svr = self.servers_client.get_server(self.instance['id'])[1]
        self.assertEqual(str(std_out).lower(),
                         str(svr['name'][:15]).lower() + '\r\n')

    # TODO: fix the bug that does not set this service running
    def _test_ntp_service_running(self):
        cmd = 'powershell (Get-Service "| where -Property Name '
        cmd += '-match W32Time").Status'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Running\r\n")

    def _test_sshpublickeys_set(self):
        pass
        # cmd =
        #check file C:\Users\<username>\.ssh\authorizedkeys_or_something
        # is not empty

        # std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        # LOG.debug(std_out)
        # LOG.debug(std_err)
        # svr = self.servers_client.get_server(self.instance['id'])[1]
        # self.assertEqual(str(std_out).lower(),
        #                  str(svr['name'][:15]).lower() + '\r\n')


    #https://github.com/cloudbase/cloudbase-init/blob/master/cloudbaseinit
    # %2Fplugins%2Fwindows%2Fsshpublickeys.py#L52
    # TODO(trobert): redo
    # def _check_userdata(self):
    #     svr = self.instance
    #     cmd = 'powershell (Get-Item "~\\Documents\\*.txt").length'
    #
    #     ip_address = floating_ip.floating_ip_address
    #     std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
    #     LOG.debug(str(std_out))
    #     LOG.debug(std_err)
    #     self.assertEqual(str(std_out), str(3))




    # def _check_services(self):
    #     self._test_services()
    #     self._test_service_keys()
    #     self._test_disk_expanded()
    #     self._test_username_created()
    #     self._test_hostname_set()
    #     pdb.set_trace()
    #     # self._test_ntp_service_running(ip_address)

    # @services('compute', 'network')
    # def test_check_services(self):
    #     self._check_services()
