#
# Cookbook Name:: vagrant
# Recipe:: sshthree
#

file '/tmp/sshthree_2.txt' do
	action :create
	owner 'root'
	group 'root'
	mode '0644'
end
