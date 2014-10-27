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
from tempest import config
from tempest.openstack.common import log as logging
from tempest.scenario import manager
from tempest.scenario import utils as test_utils
from tempest.common.utils.windows.remote_client import WinRemoteClient
import re

import base64
import subprocess
import os
import time
import pdb

LOG = logging.getLogger("cbinit")

CONF = config.CONF


class TestServices(manager.ScenarioTest):
    first_login = True

    #TODO:rtingirica add image_ref so it can be run for different images
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

        cls.security_groups = []
        cls.subnets = []
        cls.servers = []
        cls.routers = []
        cls.floating_ips = {}

        cls.default_ci_username = 'CiAdmin'
        cls.default_ci_password = 'Passw0rd'
        cls.created_user = 'Admin'
        cls.dnsmasq_neutron_path = '/etc/neutron/dnsmasq-neutron.conf'

        (resp, cls.keypair) = cls.keypairs_client.create_keypair(
            cls.__name__ + "-key")
        with open(CONF.compute.path_to_private_key, 'w') as h:
            h.write(cls.keypair['private_key'])
        metadata = {'network_config': str({'content_path':
                                            'random_value_test_random'})}

        with open(CONF.cbinit.userdata_path, 'r') as h:
            data = h.read()
            encoded_data = base64.encodestring(data)

        cls.create_test_server(wait_until='ACTIVE',
                               key_name=cls.keypair['name'],
                               disk_config='AUTO',
                               user_data=encoded_data, meta=metadata)
        cls._assign_floating_ip()

    @classmethod
    def tearDownClass(cls):
        cls.servers_client.delete_server(cls.instance['id'])
        cls.servers_client.wait_for_server_termination(cls.instance['id'])
        cls.floating_ips_client.delete_floating_ip(cls.floating_ip['id'])
        cls.keypairs_client.delete_keypair(cls.keypair['name'])

        os.remove(CONF.compute.path_to_private_key)

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
        self.change_security_group(self.instance['id'])

        self.private_network = self.get_private_network()

        self.host_name = ""
        self.instance_name = ""
        self.remote_client = WinRemoteClient(self.floating_ip['ip'],
                                             self.default_ci_username,
                                             self.default_ci_password)
        #pdb.set_trace()
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

    @classmethod
    def _assign_floating_ip(self):
        # Obtain a floating IP
        _, self.floating_ip = self.floating_ips_client.create_floating_ip()

        self.floating_ips_client.associate_floating_ip_to_server(
            self.floating_ip['ip'], self.instance['id'])

    def _decrypt_password(self, private_key, password):
        """Base64 decodes password and unencrypts it with private key.

        Requires openssl binary available in the path.
        """
        unencoded = base64.b64decode(password)
        cmd = ['openssl', 'rsautl', '-decrypt', '-inkey', private_key]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate(unencoded)
        proc.stdin.close()
        if proc.returncode:
            raise Exception(err)
        return out

    def get_private_network(self):
        networks = self.networks_client.list_networks()[1]
        for network in networks:
            if network['label'] == 'private_cbinit':
                return network

    def _get_password(self):
        enc_password = {}
        while enc_password == {}:
            (resp, enc_password) = self.servers_client.get_password(
                self.instance['id'])
        password = self._decrypt_password(
            private_key=CONF.compute.path_to_private_key,
            password=enc_password['password'])

        return password

    def _first_login(self, remote_client):
        if TestServices.first_login:
            TestServices.first_login = False

            wait_cmd = 'powershell "(Get-WmiObject Win32_Account | where -Property Name -contains CiAdmin).FullName"'
            #wait for boot completion
            LOG.info('waiting for boot completion')
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

            cmd2 = 'powershell "C:\\\\installcbinit.ps1 -newCode %s ' \
                   '-serviceType %s"' % (CONF.cbinit.replace_code,
                                         CONF.cbinit.service_type)

            LOG.info('using %s' % cmd2)

            std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd1)
            LOG.info("downloading for cbinit: " + str(std_out))
            LOG.info("downloading for cbinit: " + str(std_err))

            std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd2)
            LOG.info("installing cbinit: " + str(std_out))
            LOG.info("installing cbinit: " + str(std_err))

            key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` ' \
                  'Solutions\\Cloudbase-init\\' + self.instance['id'] + '\\Plugins'
            wait_cmd = 'powershell (Get-Item %s).ValueCount' % key

            LOG.info('waiting for server status SHUTOFF because of sysprep')
            self.servers_client.wait_for_server_status(
                server_id=self.instance['id'], status='SHUTOFF',
                extra_timeout=600)

            self.servers_client.start(self.instance['id'])

            LOG.info('waiting for server status ACTIVE')
            self.servers_client.wait_for_server_status(
                server_id=self.instance['id'], status='ACTIVE')
            #set so it does not execute before every test

            LOG.info('waiting for server to be running')
            while True:
                try:
                    std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(wait_cmd)
                    if std_err:
                        time.sleep(5)
                    elif int(std_out) >= 10:
                        break
                except:
                    time.sleep(5)

    def _get_dhcp_value(self, key):
        regexp = re.compile(r'dhcp-option-forceregex match substring in string python.' + str(key) + ',')
        f = open(self.dnsmasq_neutron_path, 'r')
        for line in f:
            re_se = regexp.search(line)
            if re_se is not None:
                return line[re_se.end():].strip('\n')

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
        #TODO: after added image to instance creation, added here as well
        image = self.images_client.get_image(CONF.compute.image_ref)
        image_size = image[1]['OS-EXT-IMG-SIZE:size']
        cmd = 'powershell (Get-WmiObject "win32_logicaldisk | where -Property DeviceID -Match C:").Size'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        self.assertTrue(int(std_out) > image_size)

    def test_username_created(self):
        cmd = 'powershell "Get-WmiObject Win32_Account | '
        cmd += 'where -Property Name -contains %s"' % self.created_user

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

    def test_ntp_service_running(self):
        cmd = 'powershell (Get-Service "| where -Property Name '
        cmd += '-match W32Time").Status'

        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Running\r\n")

    def test_password_set(self):
        password = self._get_password()
        folder_name = data_utils.rand_name("folder")

        cmd = 'mkdir C:\\%s' % folder_name
        cmd2 = 'powershell "get-childitem c:\ | select-string %s"' % folder_name
        remote_client = WinRemoteClient(self.floating_ip['ip'],
                                        self.created_user,
                                        password)

        std_out, std_err, exit_code = remote_client.run_wsman_cmd(cmd)
        std_out, std_err, exit_code = remote_client.run_wsman_cmd(cmd2)

        self.assertEqual(str(std_out.strip("\r\n")), folder_name)

    def test_sshpublickeys_set(self):
        password = self._get_password()

        cmd = 'echo %cd%'
        remote_client = WinRemoteClient(self.floating_ip['ip'],
                                        self.created_user,
                                        password)
        std_out, std_err, exit_code = remote_client.run_wsman_cmd(cmd)
        LOG.info(std_out)
        path = std_out.strip("\r\n") + '\\.ssh\\authorized_keys'

        cmd2 = 'powershell "cat %s"' % path
        std_out, std_err, exit_code = remote_client.run_wsman_cmd(cmd2)

        self.assertEqual(self.keypair['public_key'],
                         std_out.replace('\r\n', '\n'))

    def test_userdata(self):
        password = self._get_password()
        remote_client = WinRemoteClient(self.floating_ip['ip'],
                                        self.created_user,
                                        password)

        cmd = 'powershell "(Get-ChildItem -Path  C:\ *.txt).Count'
        std_out, std_err, exit_code = remote_client.run_wsman_cmd(cmd)

        LOG.debug(str(std_out))
        LOG.debug(std_err)
        # pdb.set_trace()
        self.assertEqual(std_out.strip("\r\n"), str(4))

    # TODO: get value to compare with
    # net Win32_NetworkAdapterConfiguration
    def test_mtu(self):
        cmd = 'powershell "(Get-NetIpConfiguration -Detailed).' \
              'NetIPv4Interface.NlMTU"'
        std_out, std_err, exit_code = self.remote_client.run_wsman_cmd(cmd)

        expected_mtu = self._get_dhcp_value('26')

        LOG.debug(str(std_out))
        LOG.debug(std_err)

        self.assertEqual(std_out.strip('\r\n'), expected_mtu)
