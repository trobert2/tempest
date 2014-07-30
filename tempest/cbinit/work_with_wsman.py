from tempest.common.utils.windows.remote_client import WinRemoteClient
import novaclient.client
from tempest.openstack.common import log as logging

LOG = logging.getLogger(__name__)

c = novaclient.client.Client(2, *("admin", "72a59cc788f84233", "admin","http://192.168.247.164:35357/v2.0/"),  service_type='compute', no_cache=True,insecure=True, http_log_debug=True)
s = c.servers.list()
s = c.servers.list()[0]

#check service is present
cmd1 = 'powershell (Get-Service "| where -Property Name -match cloudbase-init").DisplayName'

#get number of plugin keys
key = 'HKLM:SOFTWARE\\Wow6432Node\\Cloudbase` Solutions\\Cloudbase-init\\' + s.id + '\\Plugins'
cmd = 'powershell (Get-Item %s).ValueCount' % key

#get username this needs to be the same as Admin exactly so no -match, use -contains
cmd3 = 'powershell "Get-WmiObject Win32_Account | where -Property Name -contains Admin"'

#get hostname. this needs to be compared with the instance name
cmd4 = 'powershell (Get-WmiObject Win32_ComputerSystem).Name'

#get disk size
cmd5 = 'powershell (Get-WmiObject "win32_logicaldisk | where -Property DeviceID -Match C:").Size'
f = c.flavors.get(101)
f.disk
#get image size

wsmancmd = WinRemoteClient('192.168.104.101', 'Administrator', 'Passw0rd')
std_out, std_err, exit_code = wsmancmd.run_wsman_cmd(cmd5)
print "output:%s" % std_out
print "error:%s" % std_err
print "exit_code:%d" % exit_code


