# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'chef/provisioning/ssh_driver/version'

Gem::Specification.new do |s|
  s.name          = "chef-provisioning-ssh"
  s.version       = Chef::Provisioning::SshDriver::VERSION
  s.platform      = Gem::Platform::RUBY
  s.author        = "Zack Zondlo"
  s.email         = "zackzondlo@gmail.com"
  s.extra_rdoc_files = ['README.md', 'LICENSE' ]
  s.summary = 'Provisioner for managing servers using ssh in Chef Provisioning.'
  s.description = s.summary
  s.homepage = 'https://github.com/double-z/chef-provisioning-ssh'

  s.require_path  = "lib"
  s.bindir       = "bin"
  s.executables  = %w( )
  s.files = %w(Rakefile LICENSE README.md) + Dir.glob("{distro,lib,tasks,spec}/**/*", File::FNM_DOTMATCH).reject {|f| File.directory?(f) }

  s.add_dependency 'chef-provisioning'

  s.add_development_dependency "bundler", "~> 1.5"
  s.add_development_dependency "rspec"
  s.add_development_dependency "rake"
end
