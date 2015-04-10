require 'chef/provisioning/ssh_driver'

# require 'chef/config'
# with_chef_server "http://192.168.1.182:8889", {
#   :client_name => Chef::Config[:node_name],
#   :signing_key_filename => Chef::Config[:client_key]
# # }
# with_chef_server({ :chef_server_url => "http://192.168.1.182:8889", :options => {
#         :client_name => Chef::Config[:node_name],,
#         :signing_key_filename => Chef::Config[:client_key],
#         :local_mode => false
#       })

# with_ssh_cluster "/home/js4/metal/chef-metal/docs/examples/drivers/ssh"
# with_driver 'ssh'

with_driver 'ssh'

with_chef_server "https://api.opscode.com/organizations/zzondlo",
  :client_name => Chef::Config[:node_name],
  :signing_key_filename => Chef::Config[:client_key]

machine "winone" do
  # action :destroy
  action [:ready, :setup, :converge]
  machine_options :transport_options => {
    'is_windows' => true,
    'host' => '192.168.33.100'
  }
  #   'username' => 'vagrant',
  #   'password' => 'vagrant'
  # }
  recipe 'windows'
  converge true
end
