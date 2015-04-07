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

        attr_reader :cluster_path

        def self.from_url(driver_url, config)
          Driver.new(driver_url, config)
        end

        def initialize(driver_url, config)
          super(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          @cluster_path = cluster_path
        end

        def self.canonicalize_url(driver_url, config)
          scheme, cluster_path = driver_url.split(':', 2)
          cluster_path = File.expand_path(cluster_path || File.join(Chef::Config.config_dir, 'provisioning/ssh'))
          "ssh:#{cluster_path}"
        end

        def allocate_machine(action_handler, machine_spec, machine_options)
          ensure_ssh_cluster(action_handler) unless ::File.exists?(cluster_path)
          new_machine_options = deep_hashify(machine_options)
          machine_file_hash = updated_machine_file_hash(stringify_keys(new_machine_options),
                                                        existing_ssh_machine(machine_spec))

          raise 'machine File Hash Is Empty' unless machine_file_hash
          updated_machine_options        = deep_hashify(machine_file_hash)
          updated_machine_options_to_sym = symbolize_keys(updated_machine_options)

          validate_machine_options(action_handler, machine_spec, updated_machine_options_to_sym)
          test_connection(updated_machine_options_to_sym) if machine_spec.location

          machine_updated = create_ssh_machine_file(action_handler,
                                                    machine_spec.name,
                                                    machine_file_hash)
          if machine_updated || !machine_spec.location
            machine_spec.location = {
              'driver_url' => driver_url,
              'driver_version' => Chef::Provisioning::SshDriver::VERSION,
              'target_name' => machine_spec.name,
              'ssh_file_path' => "#{cluster_path}/#{machine_spec.name}.json",
              'allocated_at' => Time.now.utc.to_s
            }
          end
        end

        def ready_machine(action_handler, machine_spec, machine_options)
          allocate_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)
          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end
          wait_for_transport(action_handler, ssh_machine, machine_spec)
          machine_for(machine_spec, ssh_machine)
        end

        def connect_to_machine(machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)
          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end
          wait_for_transport(action_handler, ssh_machine, machine_spec)
          machine_for(machine_spec, ssh_machine)
        end

        def destroy_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)
          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end
        end

        def stop_machine(action_handler, machine_spec, machine_options)
          ssh_machine = existing_ssh_machine_to_sym(machine_spec)
          if !ssh_machine
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end
          action_handler.report_progress("SSH Machine #{machine_spec.name} is existing hardware login and power off.")
        end

        ############################
        ############################


        def updated_machine_file_hash(_new_machine_options, current_machine_options)

          new_transport_options   = deep_hashify(new_machine_options[:transport_options])
          new_convergence_options = deep_hashify(strip_hash_nil(new_machine_options[:convergence_options]))

          current_transport_options   = current_machine_options['transport_options']
          current_convergence_options = current_machine_options['convergence_options']

          transport_options_hash      = updated_transport_options_hash(stringify_keys(new_transport_options),
                                                                       current_transport_options)

          convergence_options_hash = Chef::Mixin::DeepMerge.merge(current_convergence_options,
                                                                  stringify_keys(new_convergence_options))

          new_hash = {}
          new_hash['convergence_options'] = updated_convergence_options_hash
          new_hash['transport_options']   = transport_options_hash
          new_hash
        end

        def updated_transport_options_hash(new_transport_options, current_transport_options = false)
          current_transport_options = new_transport_options unless current_transport_options
          new_ip     = new_transport_options['ip_address']     rescue false
          current_ip = current_transport_options['ip_address'] rescue false
          if (new_ip && current_ip)
            raise 'IP Addr Does not match' unless (new_ip == current_ip)
          end
          ip_address = (current_ip || new_ip)

          new_hostname     = new_transport_options['hostname']     rescue false
          current_hostname = current_transport_options['hostname'] rescue false
          hostname         = (new_hostname || current_hostname)

          new_host         = new_transport_options['host']         rescue false
          current_host     = current_transport_options['host']     rescue false
          given_host       = (new_host || current_host)

          raise 'We Gots No IP or Hostname. So, um, yeah.' unless (hostname ||
                                                                   ip_address ||
                                                                   given_host)

          new_username     = new_transport_options['username']     rescue false
          new_ssh_options_user = new_transport_options['ssh_options']['user'] rescue false
          current_username = current_transport_options['username'] rescue false
          current_ssh_options_user = current_transport_options['ssh_options']['user'] rescue false
          username         = (new_username || new_ssh_options_user || current_username || current_ssh_options_user)

          opts = {}
          opts['host']       = given_host if given_host
          opts['hostname']   = hostname   if hostname
          opts['ip_address'] = ip_address if ip_address
          host = host_for(opts)

          current_transport_options ||= {}
          current_transport_options['ssh_options'] ||= {}
          current_transport_options['ssh_options']['keys'] = [] unless current_transport_options['ssh_options']['keys']
          new_transport_options ||= {}
          new_transport_options['ssh_options'] ||= {}
          new_transport_options['ssh_options']['user'] = username
          new_transport_options['ssh_options']['keys'] = [] unless new_transport_options['ssh_options']['keys']
          new_keys = Array(current_transport_options['ssh_options']['keys']).concat( Array(new_transport_options['ssh_options']['keys']) ) || false

          new_hash = {}
          new_hash['host']                    = host
          new_hash['ip_address']              = ip_address      if ip_address
          new_hash['hostname']                = hostname        if hostname
          new_hash['ssh_options']             = {}
          new_hash['ssh_options']['keys']     = new_keys        if new_keys
          new_hash['ssh_options']['password'] = new_transport_options['password'] if new_transport_options['password']


          new_options = new_transport_options['options'] rescue {}
          options['ssh_pty_enable'] = true unless new_options.has_key?('ssh_pty_enable')
          options['prefix'] = 'sudo ' unless username == 'root'

          merged_transport_options  = Chef::Mixin::DeepMerge.merge(current_transport_options.to_hash, new_transport_options.to_hash)
          updated_transport_options = Chef::Mixin::DeepMerge.merge(deep_hashify(merged_transport_options), new_hash) unless new_hash.empty?
          ensure_has_keys_or_password(updated_transport_options)
          updated_transport_options
        end

        def ensure_has_keys_or_password(transport_hash)
          if transport_hash['ssh_options']
            ssh_hash = transport_hash['ssh_options']
            keys = ssh_hash['keys'] || false
            password = ssh_hash['password'] || false
            has_either = (password || (keys && !keys.empty?))
          else
            has_either = false
          end
          raise 'No Keys OR Password, No Can Do Compadre' unless has_either
          return has_either ? true : false
        end

        def host_for(_transport_options)
          target_host  = false
          transport_options = stringify_keys(_transport_options)

          target_ip   = transport_options['ip_address'] || false
          target_fqdn = transport_options['hostname']   || false
          target_host = transport_options['host']       || false

          raise "no target_ip or target_fqdn given" unless(target_ip ||
                                                           target_host ||
                                                           target_fqdn )
          if target_ip
            raise 'Invalid IP' unless ( target_ip =~ Resolv::IPv4::Regex ||
                                        target_ip =~ Resolv::IPv6::Regex )
            target_host = target_ip
          elsif target_fqdn
            rh = Resolv::Hosts.new
            rd = Resolv.new
            begin
              rh.getaddress(target_fqdn)
              in_hosts_file = true
            rescue
              in_hosts_file = false
            end
            begin
              rd.getaddress(target_fqdn)
              in_dns = true
            rescue
              in_dns = false
            end
            raise 'Unresolvable Hostname' unless (in_hosts_file || in_dns)
            use_host = target_fqdn
          elsif target_host
            use_host = target_host
          else
            raise "aint got no target yo, that dog dont hunt"
          end
          use_host
        end


        ############################
        ############################




        def machine_for(machine_spec, ssh_machine)

          if !ssh_machine_exists?(machine_spec)
            raise "SSH Machine #{machine_spec.name} does not have a machine file associated with it!"
          end

          if ssh_machine[:is_windows]
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
          if ssh_machine[:is_windows]
            create_winrm_transport(ssh_machine)
          else
            create_ssh_transport(ssh_machine)
          end
        end

        def convergence_strategy_for(ssh_machine)
          if ssh_machine[:is_windows]
            Chef::Provisioning::ConvergenceStrategy::InstallMsi.
              new(ssh_machine[:convergence_options], config)
          else
            Chef::Provisioning::ConvergenceStrategy::InstallSh.
              new(ssh_machine[:convergence_options], config)
          end
        end

        def create_ssh_transport(ssh_machine)
          transport_opts = ssh_machine[:transport_options]
          host = transport_opts[:host]
          username = transport_opts[:ssh_options][:user]
          ssh_options = transport_opts[:ssh_options]
          options = transport_opts[:options]
          Chef::Provisioning::Transport::SSH.new(host, username,
                                                 ssh_options, options, config)
        end

        def create_winrm_transport(ssh_machine)
          # TODO IPv6 loopback?  What do we do for that?
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

        def wait_for_transport(action_handler, ssh_machine, machine_spec)
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

        def validate_machine_options(action_handler, machine_spec, machine_options)
          error_msgs = []
          valid = true

          if !machine_options[:transport_options]
            error_msgs << ":transport_options required."
            valid = false
          else
            if machine_options[:transport_options][:is_windows]
              # Validate Windows Options.
              req_and_valid_fields = [:is_windows, [:host, :ip_address], :username, :password]
              one_of_fields = req_and_valid_fields.select{ |i| i.kind_of?(Array)}

              missing = req_and_valid_fields.flatten - machine_options[:transport_options].keys

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

              extras = machine_options[:transport_options].keys - req_and_valid_fields.flatten

              extras.each do |extra|
                error_msgs << ":transport_options => :#{extra} not allowed."
                valid = false
              end
            else
              # Validate Unix Options
              req_fields = [[:host, :ip_address], :username]
              one_of_fields = req_fields.select{ |i| i.kind_of?(Array)}

              missing = req_fields.flatten - machine_options[:transport_options].keys

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

              valid_fields = [:is_windows, :host, :ip_address, :username, :ssh_options, :options]

              extras = machine_options[:transport_options].keys - valid_fields

              extras.each do |extra|
                error_msgs << ":transport_options => :#{extra} not allowed."
                valid = false
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
                valid_fields = [:prefix, :ssh_pty_enable, :ssh_gateway]

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
          Chef::Provisioning.inline_resource(action_handler) do
            ssh_cluster _cluster_path
          end
        end

        def create_ssh_machine_file(action_handler, machine_spec, machine_options)
          log_info("File is = #{ssh_machine_file(machine_spec)}")
          log_info("current_machine_options = #{machine_options.to_s}")
          machine_options_hash = deep_hashify(machine_options)
          stringy_machine_options = stringify_keys(machine_options_hash)
          file_path = ssh_machine_file(machine_spec)
          options_parsed = ::JSON.parse(stringy_machine_options.to_json)
          json_machine_options = ::JSON.pretty_generate(options_parsed)
          Chef::Provisioning.inline_resource(action_handler) do
            file file_path do
              content json_machine_options
            end
          end
          file_path
        end

        def delete_ssh_machine_file(action_handler, machine_spec)
          if ::File.exists?(ssh_machine_file(machine_spec))
            Chef::Provisioning.inline_resource(action_handler) do
              file registry_file do
                action :delete
              end
            end
          end
        end

        def existing_ssh_machine(machine_spec)
          if ssh_machine_exists?(machine_spec)
            existing_machine_hash = JSON.parse(File.read(ssh_machine_file(machine_spec)))
            existing_machine_hash.to_hash
          else
            return false
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
          if machine_spec.location
            ::File.exists?(ssh_machine_file(machine_spec))
          else
            false
          end
        end

        def ssh_machine_file(machine_spec)
          if machine_spec.location && machine_spec.location['ssh_machine_file']
            machine_spec.location['ssh_machine_file']
          else
            ssh_machine_file = ::File.join(@cluster_path, "#{machine_spec.name}.json")
            ssh_machine_file
          end
        end
      end
    end
  end
end
