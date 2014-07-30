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

from tempest.api.network import common as net_common
from tempest.common import debug
from tempest.common.utils.data_utils import rand_name
from tempest import config
from tempest.openstack.common import log as logging
from tempest.common.utils.linux.remote_client import RemoteClient
from tempest.scenario import manager
from tempest.test import attr
from tempest.test import services
from tempest.common.utils.windows.remote_client import WinRemoteClient
import os
import time
import tempfile

LOG = logging.getLogger("cbinit")


class TestServices(manager.NetworkScenarioTest):

    CONF = config.TempestConfig()

    @classmethod
    def check_preconditions(cls):
        super(TestServices, cls).check_preconditions()
        cfg = cls.config.network
        if not (cfg.tenant_networks_reachable or cfg.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            cls.enabled = False
            raise cls.skipException(msg)

    @classmethod
    def setUpClass(cls):
        super(TestServices, cls).setUpClass()

        cls.check_preconditions()
        cls.keypairs = {}
        cls.security_groups = {}
        cls.networks = []
        cls.subnets = []
        cls.routers = []
        cls.servers = []
        cls.floating_ips = {}
        cls.default_ci_username = 'CiAdmin'
        cls.default_ci_password = 'Passw0rd'

    # def tearDownClass(cls):
    #     super(TestServices, cls).tearDownClass()
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
        svr = self.compute_client.servers.list()[0]
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

    def _get_router(self, tenant_id):
        """Retrieve a router for the given tenant id.

        If a public router has been configured, it will be returned.

        If a public router has not been configured, but a public
        network has, a tenant router will be created and returned that
        routes traffic to the public network.

        """
        router_id = self.config.network.public_router_id
        network_id = self.config.network.public_network_id
        if router_id:
            result = self.network_client.show_router(router_id)
            return net_common.AttributeDict(**result['router'])
        elif network_id:
            router = self._create_router(tenant_id)
            router.add_gateway(network_id)
            return router
        else:
            raise Exception("Neither of 'public_router_id' or "
                            "'public_network_id' has been defined.")

    def _create_router(self, tenant_id, namestart='router-smoke-'):
        name = rand_name(namestart)
        body = dict(
            router=dict(
                name=name,
                admin_state_up=True,
                tenant_id=tenant_id,
            ),
        )
        result = self.network_client.create_router(body=body)
        router = net_common.DeletableRouter(client=self.network_client,
                                            **result['router'])
        self.assertEqual(router.name, name)
        self.set_resource(name, router)
        return router

    def _create_security_groups(self):
        self.security_groups[self.tenant_id] = self._create_security_group()

    def _create_networks(self):
        #TODO: find another place to put this, like a config file
        self.config.network.tenant_networks_reachable = True
        network = self._create_network(self.tenant_id)
        router = self._get_router(self.tenant_id)
        subnet = self._create_subnet(network)
        subnet.add_to_router(router.id)
        self.networks.append(network)
        self.subnets.append(subnet)
        self.routers.append(router)

    def _check_networks(self):
        # Checks that we see the newly created network/subnet/router via
        # checking the result of list_[networks,routers,subnets]
        seen_nets = self._list_networks()
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        for mynet in self.networks:
            self.assertIn(mynet.name, seen_names)
            self.assertIn(mynet.id, seen_ids)
        seen_subnets = self._list_subnets()
        seen_net_ids = [n['network_id'] for n in seen_subnets]
        seen_subnet_ids = [n['id'] for n in seen_subnets]
        for mynet in self.networks:
            self.assertIn(mynet.id, seen_net_ids)
        for mysubnet in self.subnets:
            self.assertIn(mysubnet.id, seen_subnet_ids)
        seen_routers = self._list_routers()
        seen_router_ids = [n['id'] for n in seen_routers]
        seen_router_names = [n['name'] for n in seen_routers]
        for myrouter in self.routers:
            self.assertIn(myrouter.name, seen_router_names)
            self.assertIn(myrouter.id, seen_router_ids)

    def _create_server(self, name, network):
        tenant_id = network.tenant_id
        security_groups = [self.security_groups[tenant_id].name]

        keypair = self.create_keypair()
        self.keypairs[self.tenant_id] = keypair
        # TODO: make 2 types of instances, single userdata and
        # multipart-userdata
        handle = open("/root/tempest/tempest/cbinit/multipart_metadata")
        userdata = handle.read()

        create_kwargs = {
            'nics': [
                {'net-id': network.id},
            ],
            'security_groups': security_groups,
            'key_name': keypair.name,
            'userdata': str(userdata)
        }
        server = self.create_server(name=name, create_kwargs=create_kwargs)
        return server

    def _create_servers(self):
        for i, network in enumerate(self.networks):

            name = rand_name('test-server-%d-' % i)
            server = self._create_server(name, network)
            self.servers.append(server)

    def _assign_floating_ips(self):
        public_network_id = self.config.network.public_network_id
        for server in self.servers:
            floating_ip = self._create_floating_ip(server, public_network_id)
            self.floating_ips.setdefault(server, [])
            self.floating_ips[server].append(floating_ip)

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
        # import pdb
        # pdb.set_trace()
    #
    # def _check_tenant_network_connectivity(self):
    #     if not self.config.network.tenant_networks_reachable:
    #         msg = 'Tenant networks not configured to be reachable.'
    #         LOG.info(msg)
    #         return
    #     # The target login is assumed to have been configured for
    #     # key-based authentication by cloud-init.
    #     ssh_login = self.config.compute.image_ssh_user
    #     private_key = self.keypairs[self.tenant_id].private_key

    def _get_password(self, server_id):
        temp_key_file = tempfile.NamedTemporaryFile(mode='w+r', delete=False)
        temp_key_file.write(self.keypairs[self.tenant_id].private_key)
        temp_key_file.close()
        password = ''
        while password == '':
            password = self.compute_client.servers.get_password(
                server_id, temp_key_file.name)
        return password
        os.remove(temp_key_file.name)

    def _test_service_keys(self, pub_ip):
        svr = self.compute_client.servers.list()[0]
        key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` Solutions\\Cloudbase-init\\' + svr.id + '\\Plugins'
        cmd = 'powershell (Get-Item %s).ValueCount' % key
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        self.assertEqual(int(std_out), 11)

    def _test_services(self, pub_ip):
        username = 'Administrator'
        # TODO:Do it clean, with the right server, not first
        #but i will spawn one server per tenant creation I guess.....
        svr = self.compute_client.servers.list()[0]

        cmd = 'powershell (Get-Service "| where -Property Name -match cloudbase-init").DisplayName'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Cloud Initialization Service\r\n")

    def _test_disk_expanded(self, pub_ip):
        svr = self.compute_client.servers.list()[0]
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        # TODO: get the right image, not the first one
        image = self.compute_client.images.list()[0]
        image_size = image._info['OS-EXT-IMG-SIZE:size']
        cmd = 'powershell (Get-WmiObject "win32_logicaldisk | where -Property DeviceID -Match C:").Size'
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        self.assertTrue(int(std_out) > image_size)

    def _test_username_created(self, pub_ip):
        svr = self.compute_client.servers.list()[0]
        cmd = 'powershell "Get-WmiObject Win32_Account | where -Property Name -contains Admin"'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)

        self.assertIsNotNone(std_out)

    def _test_hostname_set(self, pub_ip):
        svr = self.compute_client.servers.list()[0]
        cmd = 'powershell (Get-WmiObject "Win32_ComputerSystem").Name'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out).lower(), str(svr.name[:15]).lower() + '\r\n')

    def _test_ntp_service_running(self, pub_ip):
        svr = self.compute_client.servers.list()[0]
        cmd = 'powershell (Get-Service "| where -Property Name -match W32Time").Status'
        wsmancmd = WinRemoteClient(pub_ip, self.default_ci_username,
                                   self.default_ci_password)
        std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
        LOG.debug(std_out)
        LOG.debug(std_err)
        self.assertEqual(str(std_out), "Running\r\n")

    def _check_userdata(self):
        svr = self.compute_client.servers.list()[0]
        cmd = 'powershell (Get-Item "~\\Documents\\*.txt").length'
        for server, floating_ips in self.floating_ips.iteritems():
            for floating_ip in floating_ips:
                ip_address = floating_ip.floating_ip_address
                wsmancmd = WinRemoteClient(ip_address,
                                           self.default_ci_username,
                                           self.default_ci_password)
                std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd)
                LOG.debug(str(std_out))
                LOG.debug(std_err)
                self.assertEqual(str(std_out), str(3))

    @services('compute', 'network')
    def test_check_services_cbinit(self):
        self._create_security_groups()
        self._create_networks()
        self._check_networks()
        self._create_servers()
        self._assign_floating_ips()
        self._check_services()

    @services('compute', 'network')
    def test_userdata_mime_type(self):
        self._create_security_groups()
        self._create_networks()
        self._create_servers()
        self._assign_floating_ips()
        time.sleep(1500)
        self._check_userdata()
