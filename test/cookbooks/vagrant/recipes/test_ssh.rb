require 'chef/provisioning/ssh_driver'

with_driver 'ssh'

machine "sshone" do
  action [:ready, :setup, :converge]
  machine_options :transport_options => {
    'ip_address' => '192.168.33.122',
    :username => 'vagrant',
    'ssh_options' => {
      :keys => ['~/.vagrant.d/insecure_private_key']

    },
    'options' => {
      'ssh_pty_enable' => true
    }
  }
  recipe 'vagrant::sshone'
  converge true
end

machine_execute "touch /tmp/test.txt" do
  machine 'sshone'
end

machine_file "/tmp/test.txt" do
  local_path "/tmp/test.txt"
  machine 'sshone'
  action :download
end

with_driver 'ssh:chef'

machine "sshtwo" do
  action [:ready, :setup, :converge]
  machine_options 'transport_options' => {
    :ip_address => '192.168.33.123',
    'username' => 'vagrant',
    :ssh_options => {
      'password' => 'vagrant'
    }
  }
  recipe 'vagrant::sshtwo'
  converge true
end

machine "sshthree" do
  action [:ready, :setup, :converge]
  machine_options :transport_options => {
    'ip_address' => '192.168.33.124',
    :username => 'vagrant',
    'ssh_options' => {
      :use_agent => true
    },
    'options' => {
      'ssh_pty_enable' => true
    }
  }
  recipe 'vagrant::sshthree'
  converge true
end

machine_execute "touch /tmp/test.txt" do
  machine 'sshthree'
end

machine_file "/tmp/test.txt" do
  local_path "/tmp/test.txt"
  machine 'sshthree'
  action :download
end
