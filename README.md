# Chef::Provisioning::Ssh

[![Build Status](https://travis-ci.org/chef/chef-provisioning-ssh.svg?branch=master)](https://travis-ci.org/chef/chef-provisioning-ssh) [![Gem Version](https://badge.fury.io/rb/chef-provisioning-ssh.svg)](http://badge.fury.io/rb/chef-provisioning-ssh)

Provisions existing machines using SSH.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'chef-provisioning-ssh'
```

And then execute:

```
$ bundle
```

Or install it yourself as:

```
$ gem install chef-provisioning-ssh
```

## Usage

### driver_url

- `with_driver 'ssh'` will store machine data in a file in the directory `.chef/provisioning/ssh` on the provisioning machine, with a reference to the file in the node attribute `node['chef_provisioning']['reference']['ssh_machine_file']`
- `with_driver 'ssh:/some/path'` will store machine data in the specified directory, with a reference to the file as above.
- `with_driver 'ssh:chef'` will store all machine data in the node attribute `node['chef_provisioning']['reference']`.

### machine_options

The `machine_options` for provisioning ssh now use the key `transport_options` which line up directly with the `transport_options` for chef-provisioning proper.

The `transport_options` key and sub-keys may be strings or symbols.

The `transport_options` can be viewed in the code for chef-provisioning here:

<https://github.com/chef/chef-provisioning/blob/master/lib/chef/provisioning/transport/ssh.rb#L17-L34>

The snippet from that link is:

```
   - host: the host to connect to, e.g. '145.14.51.45'
   - username: the username to connect with
   - ssh_options: a list of options to Net::SSH.start
   - options: a hash of options for the transport itself, including:
     - :prefix: a prefix to send before each command (e.g. "sudo ")
     - :ssh_pty_enable: set to false to disable pty (some instances don't
       support this, most do)
     - :ssh_gateway: the gateway to use, e.g. "jkeiser@145.14.51.45:222".
       nil (the default) means no gateway. If the username is omitted,
       then the default username is used instead (i.e. the user running
       chef, or the username configured in .ssh/config).

   The options are used in
     Net::SSH.start(host, username, ssh_options, options)
```

In addition to host, ip_address and hostname are also additional options.

- the `ssh_options` key accepts options from Net::SSH.start, the full list can be seen here:

  <http://net-ssh.github.io/ssh/v2/api/classes/Net/SSH.html#M000002>

- full machine_options for SSH example:

  ```ruby
    with_machine_options  :transport_options => {
            'is_windows' => false,
            'ip_address' => '192.168.33.23',
            'host' => 'somehost',
            'username' => 'vagrant',
            'ssh_options' => {
                'auth_methods' => '',
                'bind_address' => '',
                'compression' => '',
                'compression_level' => '',
                'config' => '',
                'encryption' => '',
                'forward_agent' => '',
                'hmac' => '',
                'host_key' => '',
                'keepalive' => '',
                'keepalive_interval' => '',
                'kex' => '',
                'keys' => ['/home/username/.vagrant.d/insecure_private_key'],
                'key_data' => '',
                'languages' => '',
                'logger' => '',
                'paranoid' => '',
                'password' => '',
                'port' => '',
                'proxy' => '',
                'rekey_blocks_limit' => '',
                'rekey_limit' => '',
                'rekey_packet_limit' => '',
                'timeout' => '',
                'verbose' => '',
                'global_known_hosts_file' => '',
                'user_known_hosts_file' => '',
                'host_key_alias' => '',
                'host_name' => '',
                'user' => '',
                'properties' => '',
                'passphrase' => '',
                'keys_only' => '',
                'max_pkt_size' => '',
                'max_win_size, :send_env' => '',
                'use_agent' => ''
            },
            'options' => {
              'prefix' => 'sudo ',
              'ssh_pty_enable' => false,
              'ssh_gateway' => 'yourgateway'
            }
          }
  ```

- full machine_options for WinRM example:

  ```ruby
    with_machine_options  :transport_options => {
                'is_windows' => true,
                'host' => '192.168.33.23',
                'port' => 5985,
                'username' => 'vagrant',
                'password' => 'vagrant'
            }
  ```

- machine resource example:

  ```ruby
        require 'chef/provisioning/ssh_driver'

        with_driver 'ssh'

        machine "ssh" do
          action [:ready, :setup, :converge]
          machine_options :transport_options => {
            'ip_address' => '192.168.33.22',
            'username' => 'vagrant',
            'ssh_options' => {
              'password' => 'vagrant'
            }
          }
          recipe 'vagrant::sshone'
          converge true
        end

        ##
        # With WinRM you must use a remote chef-server
        # local-mode chef server is not currently supported

        with_chef_server "https://api.opscode.com/organizations/double-z",
                         :client_name => Chef::Config[:node_name],
                         :signing_key_filename => Chef::Config[:client_key]

        machine "winrm" do
          action [:ready, :setup, :converge]
          machine_options :transport_options => {
            'is_windows' => true,
            'host' => '192.168.33.23',
            'port' => 5985,
            'username' => 'vagrant',
            'password' => 'vagrant'
          }
          recipe 'windows'
          converge true
        end
  ```

To test it out, clone the repo:

`git clone https://github.com/chef/chef-provisioning-ssh.git`

in the test directory there is a Vagrantfile with 2 nodes.

Run:

`vagrant up`

which will bring up both nodes.

Then run from the test directory:

`chef-client -z -o vagrant::test_ssh`

NOTE: if the first machine fails it will likely be a result of issues with your vagrant key.

This will run chef-provisioning on each of the two vagrant nodes.

thats it.

party on wayne.

Be aware, the `test_ssh` recipe is designed for testing, not to illustrate good practice. For example, you do not need to list all three actions `[ :ready, :setup, :converge ]` or specify `converge true` if you want the normal 'bootstrap if needed, converge if changed' behavior.

## Contributing

1. Fork it ( <http://github.com/chef/chef-provisioning-ssh/fork> )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
