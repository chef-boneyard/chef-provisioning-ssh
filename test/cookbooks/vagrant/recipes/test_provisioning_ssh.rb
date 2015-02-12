chef_gem 'chef-provisioning-ssh'
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
machine "sshone" do
  # action :destroy
  action [:ready, :setup, :converge]
  machine_options 'transport_options' => {
    'ip_address' => '192.168.33.22',
    'username' => 'vagrant',
    'ssh_options' => {
      'password' => 'vagrant'
    }
  }
  recipe 'vagrant::sshone'
  converge true
end

machine "sshtwo" do
  # action :destroy
  action [:ready, :setup, :converge]
  machine_options :transport_options => {
    'ip_address' => '192.168.33.23',
    'username' => 'vagrant',
    'ssh_options' => {
      'keys' => ["#{ENV['HOME']}/.vagrant.d/insecure_private_key"]
    }
  }
  recipe 'vagrant::sshtwo'
  converge true
end

