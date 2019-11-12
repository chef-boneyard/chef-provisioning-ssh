require 'json'
require 'resolv'
require 'chef/provisioning/driver'
require 'chef/provisioning/version'
require 'chef/provisioning/machine/basic_machine'
require 'chef/provisioning/machine/unix_machine'
require 'chef/provisioning/machine/windows_machine'
require 'chef/provisioning/convergence_strategy/install_msi'
require 'chef/provisioning/convergence_strategy/install_sh'
require 'chef/provisioning/transport/winrm'
require 'chef/provisioning/transport/ssh'
require 'chef/provisioning/ssh_driver/version'
require 'chef/provisioning/ssh_driver/helpers'
require 'chef/resource/ssh_cluster'
require 'chef/provider/ssh_cluster'

class Chef
  module Provisioning
    module SshDriver
      # Provisions Machines Using SSH.
      class Driver < Chef::Provisioning::Driver

        include Chef::Provisioning::SshDriver::Helpers

        # cluster_path is where the driver stores machine data unless use_chef_store is true
        attr_reader :cluster_path
        
        # use_chef_store is true if the driver_url is 'ssh:chef'
        # In this case, machine data is stored in chef
        # under node['chef_provisioning']['reference']['machine_options']
        attr_reader :use_chef_store

        def self.from_url(driver_url, config)
          Driver.new(driver_url, config)
        end

        def initialize(driver_url, config)
          super(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          @cluster_path = cluster_path
          @use_chef_store = cluster_path == 'chef' 
        end

        def self.canonicalize_url(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          unless cluster_path == 'chef'
            cluster_path = File.expand_path(cluster_path || File.join(Chef::Config.config_dir, 'provisioning/ssh'))
          end
          "ssh:#{cluster_path}"
        end

        def allocate_machine(action_handler, machine_spec, machine_options)
          ssh_machine_options = prepare_machine_options(action_handler, machine_spec, machine_options)
          log_info("current_machine_options = #{ssh_machine_options.to_s}")
          
          unless ssh_machine_exists?(machine_spec)
            machine_spec.reference = {
              'driver_url' => driver_url,
              'driver_version' => Chef::Provisioning::SshDriver::VERSION,
              'target_name' => machine_spec.name,
              'allocated_at' => Time.now.utc.to_s,
              'host' => action_handler.host_node
            }
          end
          
          update_ssh_machine(action_handler, machine_spec, ssh_machine_options)

          if machine_spec.reference && 
            (machine_spec.reference['driver_version'] != Chef::Provisioning::SshDriver::VERSION)
            machine_spec.reference['driver_version'] = Chef::Provisioning::SshDriver::VERSION
          end
        end

        def ready_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)

          unless ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have machine options associated with it!"
          end

          wait_for_transport(action_handler, ssh_machine, machine_spec, machine_options)
          machine_for(machine_spec, machine_options)
        end

        def connect_to_machine(machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)
          machine_for(machine_spec, ssh_machine)
        end

        def destroy_machine(action_handler, machine_spec, machine_options)
          ssh_machine = ssh_machine_exists?(machine_spec)

          unless ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have machine options associated with it!"
          end
          
          unless use_chef_store
            Chef::Provisioning.inline_resource(action_handler) do
              file machine_spec.reference['ssh_machine_file'] do
                action :delete
                backup false
              end
            end
          end 
        end

        def stop_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)

          unless ssh_machine && machine_spec.reference['machine_options']
            raise "SSH Machine #{machine_spec.name} does not have machine options associated with it!"
          end

          action_handler.report_progress("SSH Machine #{machine_spec.name} is existing hardware login and power off.")
        end

        def machine_for(machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)

          unless ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have machine options associated with it!"
          end

          if ssh_machine[:transport_options][:is_windows]
            Chef::Provisioning::Machine::WindowsMachine.new(machine_spec,
                                                            transport_for(ssh_machine),
                                                            convergence_strategy_for(ssh_machine))
          else
            Chef::Provisioning::Machine::UnixMachine.new(machine_spec,
                                                         transport_for(ssh_machine),
                                                         convergence_strategy_for(ssh_machine))
          end
        end

        def transport_for(ssh_machine)
          if ssh_machine[:transport_options][:is_windows]
            create_winrm_transport(ssh_machine)
          else
            create_ssh_transport(ssh_machine)
          end
        end

        def convergence_strategy_for(ssh_machine)
          if ssh_machine[:transport_options][:is_windows]
            Chef::Provisioning::ConvergenceStrategy::InstallMsi.
              new(ssh_machine[:convergence_options], config)
          else
            Chef::Provisioning::ConvergenceStrategy::InstallSh.
              new(ssh_machine[:convergence_options], config)
          end
        end

        def create_ssh_transport(ssh_machine)
          hostname    = ssh_machine[:transport_options][:host]
          username    = ssh_machine[:transport_options][:username]
          ssh_options = ssh_machine[:transport_options][:ssh_options]
          options     = ssh_machine[:transport_options][:options]
          Chef::Provisioning::Transport::SSH.new(hostname, username,
                                                 ssh_options, options, config)
        end

        def create_winrm_transport(ssh_machine)
          # # TODO IPv6 loopback?  What do we do for that?
          hostname = ssh_machine[:transport_options][:host] ||
            ssh_machine[:transport_options][:ip_address]
          port = ssh_machine[:transport_options][:port] || 5985
          # port = forwarded_ports[port] if forwarded_ports[port]
          endpoint = "http://#{hostname}:#{port}/wsman"
          type = :plaintext
          options = {
            :user => ssh_machine[:transport_options][:username],
            :pass => ssh_machine[:transport_options][:password],
            :disable_sspi => true
          }
          Chef::Provisioning::Transport::WinRM.new(endpoint, type, options, config)
        end

        def wait_for_transport(action_handler, ssh_machine, machine_spec, machine_options)
          time_elapsed = 0
          sleep_time = 10
          max_wait_time = 120
          transport = transport_for(ssh_machine)
          unless transport.available?
            if action_handler.should_perform_actions
              action_handler.report_progress "waiting for #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) to be connectable (transport up and running) ..."
              while time_elapsed < max_wait_time && !transport.available?
                action_handler.report_progress "been waiting #{time_elapsed}/#{max_wait_time} -- sleeping #{sleep_time} seconds for #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) to be connectable ..."
                sleep(sleep_time)
                time_elapsed += sleep_time
              end
              unless transport.available?
                raise "Machine #{machine_spec.name} (#{ssh_machine[:transport_options][:ip_address]} on #{driver_url}) did not become ready within 120 seconds"
              end
              action_handler.report_progress "#{machine_spec.name} is now connectable"
            end
          end
        end

        def validate_transport_fields(options, req_fields, opt_fields)
          error_msgs = []
          valid_fields = req_fields.flatten + opt_fields
          one_of_fields = req_fields.select{ |i| i.kind_of?(Array)}

          missing = req_fields.flatten - options.keys

          one_of_fields.each do |oof|
            if oof == oof & missing
              error_msgs << ":transport_options => :#{oof.join(" or :")} required."
            end
            missing -= oof
          end

          missing.each do |missed|
            error_msgs << ":transport_options => :#{missed} required."
            valid = false
          end

          extras = options.keys - valid_fields

          extras.each do |extra|
            error_msgs << ":transport_options => :#{extra} not allowed."
            valid = false
          end
          
          error_msgs
        end
        
        def validate_machine_options(action_handler, machine_spec, machine_options)
          error_msgs = []
          valid = true
          
          unless machine_options[:transport_options]
            error_msgs << ":transport_options required."
            valid = false
          else
            if machine_options[:transport_options][:is_windows]
              # Validate Windows Options.
              field_errors = validate_transport_fields(
                machine_options[:transport_options],
                [:is_windows, [:host, :ip_address], :username, :password], 
                [:port]
              )
              unless field_errors.empty?
                valid = false
                error_msgs << field_errors
              end
            else
              # Validate Unix Options
              field_errors = validate_transport_fields(
                machine_options[:transport_options],
                [[:host, :hostname, :ip_address], :username], 
                [:is_windows, :host, :hostname, :ip_address, :username, :ssh_options, :options]
              )
              
              unless field_errors.empty?
                valid = false
                error_msgs << field_errors
              end

              if machine_options[:transport_options][:ssh_options]
                valid_fields = valid_ssh_options

                extras = machine_options[:transport_options][:ssh_options].keys - valid_fields

                extras.each do |extra|
                  error_msgs << ":transport_options => ssh_options => :#{extra} not allowed."
                  valid = false
                end
              end

              if machine_options[:transport_options][:options]
                valid_fields = [:prefix, :ssh_pty_enable, :ssh_gateway, :scp_temp_dir]

                extras = machine_options[:transport_options][:options].keys - valid_fields

                extras.each do |extra|
                  error_msgs << ":transport_options => :options => :#{extra} not allowed."
                  valid = false
                end
              end
            end
          end

          if !valid
            exception_string = "Machine Options for #{machine_spec.name} are invalid cannot create machine."
            error_msgs.each do |string|
              exception_string = "#{exception_string}\n  #{string}"
            end
            raise exception_string
          end
        end

        def ensure_ssh_cluster(action_handler)
          _cluster_path = cluster_path
          unless ::File.exists?(_cluster_path)
            Chef::Provisioning.inline_resource(action_handler) do
              ssh_cluster _cluster_path
            end
          end
        end

        def create_machine_file(action_handler, machine_spec, machine_options_hash)
          ensure_ssh_cluster(action_handler)

          file_path = ssh_machine_file(machine_spec)
          stringy_machine_options = stringify_keys(machine_options_hash)
          options_parsed = ::JSON.parse(stringy_machine_options.to_json)
          json_machine_options = ::JSON.pretty_generate(options_parsed)
          log_info("File is = #{file_path}")
          Chef::Provisioning.inline_resource(action_handler) do
            file file_path do
              content json_machine_options
            end
          end
          file_path
        end

        def delete_ssh_machine(action_handler, machine_spec)
          if ::File.exists?(ssh_machine_file(machine_spec))
            Chef::Provisioning.inline_resource(action_handler) do
              file registry_file do
                action :delete
              end
            end
          end
        end

        def existing_ssh_machine(machine_spec)
          unless ssh_machine_exists?(machine_spec)
            return {}
          end
          
          if use_chef_store
            machine_spec.reference['machine_options']
          else
            JSON.parse(File.read(ssh_machine_file(machine_spec))).to_hash
          end
        end

        def existing_ssh_machine_to_sym(machine_spec)
          if ssh_machine_exists?(machine_spec)
            existing_machine_hash = existing_ssh_machine(machine_spec)
            symbolize_keys(existing_machine_hash)
          else
            return false
          end
        end

        def ssh_machine_exists?(machine_spec)
          if use_chef_store
            machine_spec.reference && machine_spec.reference['machine_options']
          else
            machine_spec.reference && ::File.exists?(ssh_machine_file(machine_spec))
          end
        end

        def ssh_machine_file(machine_spec)
          if machine_spec.reference && machine_spec.reference['ssh_machine_file']
            machine_spec.reference['ssh_machine_file']
          else
            ssh_machine_file = ::File.join(@cluster_path, "#{machine_spec.name}.json")
            ssh_machine_file
          end
        end

        def prepare_machine_options(action_handler, machine_spec, machine_options)
          options_hash = symbolize_keys(deep_hashify(machine_options))
          
          # if no transport options are specified, use the existing ones
          unless options_hash[:transport_options]
            ssh_machine = existing_ssh_machine_to_sym(machine_spec) || {}
            options_hash[:transport_options] = ssh_machine[:transport_options]  || {}
          end
          
          validate_machine_options(action_handler, machine_spec, options_hash)
          create_machine_hash(stringify_keys(options_hash))
        end
        
        def update_ssh_machine(action_handler, machine_spec, ssh_machine_options)
          unless existing_ssh_machine(machine_spec).eql? ssh_machine_options
            if use_chef_store
              machine_spec.reference['machine_options'] = ssh_machine_options
            else
              machine_spec.reference['ssh_machine_file'] = 
                create_machine_file(action_handler, machine_spec, ssh_machine_options)
            end
            machine_spec.reference['updated_at'] = Time.now.utc.to_s
          end
        end

        def create_machine_hash(machine_options)
          if !machine_options['transport_options']['host']
            machine_options['transport_options']['host'] = machine_options['transport_options']['ip_address'] ||
              machine_options['transport_options']['hostname']
          end
          validate_transport_options_host(machine_options['transport_options']['host'])
          unless machine_options['transport_options']['is_windows']
            machine_options['transport_options']['options'] ||= {}
            unless machine_options['transport_options']['username'] == 'root'
              machine_options['transport_options']['options']['prefix'] ||= 'sudo '
            end
          end
          ensure_has_keys_or_password(machine_options['transport_options'])
          machine_options.to_hash
        end

        def ensure_has_keys_or_password(transport_hash)
          if transport_hash['is_windows']
            password = transport_hash['password'] || false
            has_either = (password && password.kind_of?(String))
          else
            if transport_hash['ssh_options']
              ssh_hash = transport_hash['ssh_options']
              keys = ssh_hash['keys'] || false
              key_data = ssh_hash['key_data'] || false
              password = ssh_hash['password'] || false
              agent = ssh_hash['use_agent'] || false
              has_either = ((password && password.kind_of?(String)) ||
                            (keys && !keys.empty? && keys.kind_of?(Array)) ||
                            (key_data && !key_data.empty? && key_data.kind_of?(Array)) ||
                            agent)
            else
              has_either = false
            end
          end
          raise 'No Keys, Password, or SSH Agent configured' unless has_either
          has_either
        end

        def validate_transport_options_host(target_host)
          rh = Resolv::Hosts.new
          rd = Resolv.new

          begin
            rh.getaddress(target_host)
            in_hosts_file = true
          rescue
            in_hosts_file = false
          end

          begin
            rd.getaddress(target_host)
            in_dns = true
          rescue
            in_dns = false
          end

          valid_ip = ( target_host =~ Resolv::IPv4::Regex ||
                       target_host =~ Resolv::IPv6::Regex )

          raise 'Host is not a Valid IP or Resolvable Hostname' unless ( valid_ip || in_hosts_file || in_dns )
        end
      end
    end
  end
end
