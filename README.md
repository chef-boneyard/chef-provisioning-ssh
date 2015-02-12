[![Gem Version](https://badge.fury.io/rb/chef-provisioning-ssh.svg)](http://badge.fury.io/rb/chef-provisioning-ssh)

# Chef::Provisioning::Ssh

TODO: Write a gem description

## Installation

Add this line to your application's Gemfile:
e 
```ruby
gem 'chef-provisioning-ssh'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install chef-provisioning-ssh

## Usage

The `machine_options` for provisioning ssh now use the key `transport_options` which line up directly with the `transport_options` for chef-provisioning proper. Transport_options can be a string or symbol and will be properly converted. The transport_options can be viewed in the code for chef-provisioning here:

https://github.com/chef/chef-provisioning/blob/master/lib/chef/provisioning/transport/ssh.rb#L17-L34

The snippet from that link is:

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
         Net::SSH.start(host, username, ssh_options)

In addition to host, ip_address and hostname are also additional options.

* valid ssh options are:

        :auth_methods, 
        :bind_address, 
        :compression, 
        :compression_level, 
        :config,
        :encryption, 
        :forward_agent, 
        :hmac, 
        :host_key,
        :keepalive, 
        :keepalive_interval, 
        :kex, 
        :keys, 
        :key_data,
        :languages, 
        :logger, 
        :paranoid, 
        :password, 
        :port, 
        :proxy,
        :rekey_blocks_limit,
        :rekey_limit, 
        :rekey_packet_limit, 
        :timeout, 
        :verbose,
        :global_known_hosts_file, 
        :user_known_hosts_file, 
        :host_key_alias,
        :host_name, 
        :user, 
        :properties, 
        :passphrase, 
        :keys_only, 
        :max_pkt_size,
        :max_win_size, :send_env, 
        :use_agent

* machine resource example:

			require 'chef/provisioning/ssh_driver'

			with_driver 'ssh'

			machine "sshone" do
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
			  action [:ready, :setup, :converge]
			  machine_options :transport_options => {
			    'ip_address' => '192.168.33.23',
			    'username' => 'vagrant',
			    'ssh_options' => {
			      'keys' => ['/home/username/.vagrant.d/insecure_private_key']
			    }
			  }
			  recipe 'vagrant::sshtwo'
			  converge true
			end


To test it out, clone the repo:

`git clone https://github.com/double-z/chef-provisioning-ssh.git`

in the test directory there is a Vagrantfile with 2 nodes. 

Run:

`vagrant up`

which will bring up both nodes. 

Then run from the test directory:

`chef-client -z -o vagrant::test_provisioning_ssh`

This will run chef-provisioning on each of the two vagrant nodes.

thats it.

party on wayne.

## Contributing

1. Fork it ( http://github.com/double-z/chef-provisioning-ssh/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request