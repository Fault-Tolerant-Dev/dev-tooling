cis_level = input('cis_level')
#distro_name = input('distro_name')

title '1.1 Filesystem Configuration'


container_execution = begin
  virtualization.role == 'guest' && virtualization.system =~ /^(lxc|docker)$/
rescue NoMethodError
  false
end



control 'cis-dil-benchmark-1.1.1.1' do
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc  "Test 1"
  impact 1.0
  only_if { container_execution }

  tag cis: 'distribution-independent-linux:1.1.1.1'
  tag level: 1
  tag distro: 'alpine'

 describe file('/proc/1/cgroup') do
    its('content') { should include 'docker' }

end
end
control 'cis-dil-benchmark-1.1.1.2' do
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc  "Test 2"
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.2'
  tag level: 2
  tag distro: 'alpine'
  
  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
  
end

control 'cis-dil-benchmark-1.1.1.3' do
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc  "Test 3"
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.3'
  tag level: 1
  tag distro: 'alpine'

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
  end


end

control 'cis-dil-benchmark-3.3.5' do
  title 'Ensure permissions on /etc/hosts.deny are configured'
  desc "Test 4"
  impact 1.0

  tag cis: 'distribution-independent-linux:3.3.5'
  tag level: 2
  tag distro: 'alpine'

  describe file('/etc/hosts.deny') do
    it { should exist }
    it { should be_file }

    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }

    its('mode') { should cmp '0644' }
  end
   only_if { distro_name == derp }
end


#describe file('/proc/1/cgroup') do
#    its('content') { should include 'docker' }
