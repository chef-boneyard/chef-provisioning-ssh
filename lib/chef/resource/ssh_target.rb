# require 'chef/resource/lwrp_base'

# class Chef::Resource::SshTarget < Chef::Resource::LWRPBase

#   self.resource_name = 'ssh_target'
  
#   actions :register, :update

#   default_action :register

#   attribute :ip_address,
#   	:kind_of => [String],
#   	:name => true

#   # TODO, get path from cluster resource
#   attribute :ssh_cluster_path,
#   	:kind_of => [String]

#   attribute :mac_address,
#   	:kind_of => [String],
#   	:default => ""

#   attribute :hostname,
#   	:kind_of => [String],
#   	:default => ""

#   attribute :password,
#     :kind_of => [String],
#     :default => ""
 
#   attribute :key,
#     :kind_of => [String],
#     :default => ""
 
#   attribute :subnet,
#   	:kind_of => [String],
#   	:default => ""

#   attribute :domain,
#   	:kind_of => [String],
#   	:default => ""

#   attribute :fqdn,
#   	:kind_of => [String],
#   	:default => ""

#   attribute :available, 
#   	:kind_of => [String],
#   	:default => "true"

#   attribute :machine_types, 
#   	:kind_of => [Array],
#   	:default => Array.new

#   attribute :memory, 
#   	:kind_of => [String],
#   	:default => ""

#   attribute :cpu_count, 
#   	:kind_of => [String],
#   	:default => ""

#   attribute :cpu_type, 
#   	:kind_of => [String],
#   	:default => ""

#   attribute :arch, 
#   	:kind_of => [String],
#   	:default => ""

# end
