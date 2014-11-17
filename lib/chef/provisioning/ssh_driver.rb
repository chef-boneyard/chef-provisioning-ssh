require 'chef/provisioning'
require 'chef/resource/ssh_cluster'
require 'chef/provider/ssh_cluster'
require 'chef/provisioning/ssh_driver/version'
require 'chef/provisioning/ssh_driver/driver'

class Chef
  module Provisioning
    module SshDriver
    end
  end
end

class Chef
  module DSL
    module Recipe
      def with_ssh_cluster(cluster_path, &block)
        with_driver("ssh:#{cluster_path}", &block)
      end
    end
  end
end
