# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

cis_level = input('cis_level')

title '1.1 Filesystem Configuration'

control 'cis-dil-benchmark-1.1.1.1' do
  title 'Ensure mounting of cramfs filesystems is disabled'
  desc  "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.1'
  tag level: 1

  describe kernel_module('cramfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.2' do
  title 'Ensure mounting of freevxfs filesystems is disabled'
  desc  "The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.2'
  tag level: 1

  describe kernel_module('freevxfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.3' do
  title 'Ensure mounting of jffs2 filesystems is disabled'
  desc  "The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.3'
  tag level: 1

  describe kernel_module('jffs2') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.4' do
  title 'Ensure mounting of hfs filesystems is disabled'
  desc  "The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.4'
  tag level: 1

  describe kernel_module('hfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.5' do
  title 'Ensure mounting of hfsplus filesystems is disabled'
  desc  "The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.5'
  tag level: 1

  describe kernel_module('hfsplus') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.6' do
  title 'Ensure mounting of squashfs filesystems is disabled'
  desc  "The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs). A squashfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.6'
  tag level: 1

  describe kernel_module('squashfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.7' do
  title 'Ensure mounting of udf filesystems is disabled'
  desc  "The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.7'
  tag level: 1

  describe kernel_module('udf') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end

control 'cis-dil-benchmark-1.1.1.8' do
  title 'Ensure mounting of FAT filesystems is disabled'
  desc  "The FAT filesystem format is primarily used on older windows systems and portable USB drives or flash modules. It comes in three types FAT12, FAT16, and FAT32 all of which are supported by the vfat kernel module.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.1.8'
  tag level: 2

  describe kernel_module('vfat') do
    it { should_not be_loaded }
    it { should be_disabled }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.2' do
  title 'Ensure separate partition exists for /tmp'
  desc  "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.2'
  tag level: 1

  describe mount('/tmp') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.3' do
  title 'Ensure nodev option set on /tmp partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.3'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.4' do
  title 'Ensure nosuid option set on /tmp partition'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.4'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'nosuid' }
  end
end

control 'cis-dil-benchmark-1.1.5' do
  title 'Ensure noexec option set on /tmp partition'
  desc "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.5'
  tag level: 1

  describe mount('/tmp') do
    its('options') { should include 'noexec' }
  end
end

control 'cis-dil-benchmark-1.1.6' do
  title 'Ensure separate partition exists for /var'
  desc  "The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.\n\nRationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.6'
  tag level: 2

  describe mount('/var') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.7' do
  title 'Ensure separate partition exists for /var/tmp'
  desc  "The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.7'
  tag level: 2

  describe mount('/var/tmp') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.8' do
  title 'Ensure nodev option set on /var/tmp partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.8'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'nodev' }
  end

end

control 'cis-dil-benchmark-1.1.9' do
  title 'Ensure nosuid option set on /var/tmp partition'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.9'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'nosuid' }
  end

end

control 'cis-dil-benchmark-1.1.10' do
  title 'Ensure noexec option set on /var/tmp partition'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.10'
  tag level: 1

  only_if('/var/tmp is mounted') do
    mount('/var/tmp').mounted?
  end

  describe mount('/var/tmp') do
    its('options') { should include 'noexec' }
  end

end

control 'cis-dil-benchmark-1.1.11' do
  title 'Ensure separate partition exists for /var/log'
  desc  "The /var/log directory is used by system services to store log data .\n\nRationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.11'
  tag level: 2

  describe mount('/var/log') do
    it { should be_mounted }
  end
  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.1.12' do
  title 'Ensure separate partition exists for /var/log/audit'
  desc  "The auditing daemon, auditd, stores log data in the /var/log/audit directory.\n\nRationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog) consume space in the same partition as auditd, it may not perform as desired."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.12'
  tag level: 2

  only_if { cis_level == 2 }

  describe mount('/var/log/audit') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.13' do
  title 'Ensure separate partition exists for /home'
  desc  "The /home directory is used to support disk storage needs of local users.\n\nRationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.13'
  tag level: 2

  only_if { cis_level == 2 }

  describe mount('/home') do
    it { should be_mounted }
  end
end

control 'cis-dil-benchmark-1.1.14' do
  title 'Ensure nodev option set on /home partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.14'
  tag level: 1

  only_if('/home is mounted') do
    mount('/home').mounted?
  end

  describe mount('/home') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.15' do
  title 'Ensure nodev option set on /dev/shm partition'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.15'
  tag level: 1

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end

  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

control 'cis-dil-benchmark-1.1.16' do
  title 'Ensure nosuid option set on /dev/shm partitionrun'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.16'
  tag level: 1

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end

  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

control 'cis-dil-benchmark-1.1.17' do
  title 'Ensure noexec option set on /dev/shm partition'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.17'
  tag level: 1

  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end

  only_if('/dev/shm is mounted') do
    mount('/dev/shm').mounted?
  end
end

control 'cis-dil-benchmark-1.1.18' do
  title 'Ensure nodev option set on removable media partitions'
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.18'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.18' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.19' do
  title 'Ensure nosuid option set on removable media partitions'
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.19'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.19' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.20' do
  title 'Ensure noexec option set on removable media partitions'
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from the removable media. This deters users from being able to introduce potentially malicious software on the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.1.20'
  tag level: 1

  describe 'cis-dil-benchmark-1.1.20' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.1.21' do
  title 'Ensure sticky bit is set on all world-writable directories'
  desc  "Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.\n\nRationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.21'
  tag level: 1

  describe command("df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)") do
    its('stdout') { should cmp '' }
  end
end

control 'cis-dil-benchmark-1.1.22' do
  title 'Disable Automounting'
  desc  "autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.\n\nRationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.22'
  tag level: 1

  describe.one do
    describe service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end

    describe systemd_service('autofs') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  end
end

control 'cis-dil-benchmark-1.1.23' do
  title 'Disable USB Storage'
  desc  '
    USB storage provides a means to transfer and store files insuring persistence and availability of the files independent of network connection status.
    Its popularity and utility has led to USB-based malware being a simple and common means for network infiltration and a first step to establishing
    a persistent threat within a networked environment.
  '
  impact 1.0

  tag cis: 'distribution-independent-linux:1.1.23'
  tag level: 1

  # kernel modules need to use underscores
  # ref: https://github.com/inspec/inspec/issues/5190
  describe kernel_module('usb_storage') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.2 Configure Software Updates'

control 'cis-dil-benchmark-1.2.1' do
  title 'Ensure package manager repositories are configured'
  desc  "Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.\n\nRationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.2.1'
  tag level: 1

  describe 'cis-dil-benchmark-1.2.1' do
    skip 'Not implemented'
  end
end

control 'cis-dil-benchmark-1.2.2' do
  title 'Ensure GPG keys are configured'
  desc  "Most packages managers implement GPG key signing to verify package integrity during installation.\n\nRationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.2.2'
  tag level: 1

  describe 'cis-dil-benchmark-1.2.2' do
    skip 'Not implemented'
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek
#

title '1.3 Filesystem Integrity Checking'

control 'cis-dil-benchmark-1.3.1' do
  title 'Ensure AIDE is installed'
  desc  "AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.\n\nRationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.3.1'
  tag level: 1

  describe.one do
    describe package('aide') do
      it { should be_installed }
    end

    describe command('aide') do
      it { should exist }
    end
  end
end

control 'cis-dil-benchmark-1.3.2' do
  title 'Ensure filesystem integrity is regularly checked'
  desc  "Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.\n\nRationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.3.2'
  tag level: 1

  describe.one do
    %w[/var/spool/cron/crontabs/root /var/spool/cron/root /etc/crontab].each do |f|
      describe file(f) do
        its('content') { should match(/aide (--check|-C)/) }
      end
    end

    %w[cron.d cron.hourly cron.daily cron.weekly cron.monthly].each do |f|
      command("find /etc/#{f} -type f").stdout.split.each do |entry|
        describe file(entry) do
          its('content') { should match(/aide (--check|-C)/) }
        end
      end
    end
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.4 Secure Boot Settings'

control 'cis-dil-benchmark-1.4.1' do
  title 'Ensure permissions on bootloader config are configured'
  desc  "The grub configuration file contains information on boot settings and passwords for unlocking boot options. The grub configuration is usually grub.cfg stored in /boot/grub.\n\nRationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.4.1'
  tag level: 1

  describe.one do
    grub_conf.locations.each do |f|
      describe file(f) do
        it { should exist }
        it { should_not be_readable.by 'group' }
        it { should_not be_writable.by 'group' }
        it { should_not be_executable.by 'group' }
        it { should_not be_readable.by 'other' }
        it { should_not be_writable.by 'other' }
        it { should_not be_executable.by 'other' }
        its(:gid) { should cmp 0 }
        its(:uid) { should cmp 0 }
      end
    end
  end
end

control 'cis-dil-benchmark-1.4.2' do
  title 'Ensure bootloader password is set'
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.4.2'
  tag level: 1

  describe.one do
    grub_conf.locations.each do |f|
      describe file(f) do
        its(:content) { should match(/^set superusers/) }
        its(:content) { should match(/^password/) }
      end
    end
  end
end

control 'cis-dil-benchmark-1.4.3' do
  title 'Ensure authentication required for single user mode'
  desc  "Single user mode is used for recovery when the system detects an issue during boot or by manual selection from the bootloader.\n\nRationale: Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.4.3'
  tag level: 1

  describe.one do
    describe shadow.users('root') do
      its(:passwords) { should_not include('*') }
      its(:passwords) { should_not include('!') }
    end

    describe file('/etc/inittab') do
      its(:content) { should match(%r{^~~:S:respawn:/sbin/sulogin}) }
    end

    describe file('/etc/sysconfig/init') do
      its(:content) { should match(%r{^SINGLE=/sbin/sulogin$}) }
    end
  end
end

control 'cis-dil-benchmark-1.4.4' do
  title 'Ensure interactive boot is not enabled'
  desc  "Interactive boot allows console users to interactively select which services start on boot. Not all distributions support this capability.\nThe PROMPT_FOR_CONFIRM option provides console users the ability to interactively boot the system and select which services to start on boot .\n\nRationale: Turn off the PROMPT_FOR_CONFIRM option on the console to prevent console users from potentially overriding established security settings."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.4.4'
  tag level: 1

  if file('/etc/sysconfig/boot').exist?
    describe file('/etc/sysconfig/boot') do
      its(:content) { should match(/^PROMPT_FOR_CONFIRM="no"$/) }
    end
  else
    describe 'cis-dil-benchmark-1.4.4' do
      skip 'Not implemented'
    end
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.5 Additional Process Hardening'

control 'cis-dil-benchmark-1.5.1' do
  title 'Ensure core dumps are restricted'
  desc  "A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.\n\nRationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.1'
  tag level: 1

  describe.one do
    describe file('/etc/security/limits.conf') do
      its(:content) { should match(/^\s*\*\s+hard\s+core\s+0\s*(?:#.*)?$/) }
    end

    command('find /etc/security/limits.d -type f').stdout.split.each do |f|
      describe file(f) do
        its(:content) { should match(/^\s*\*\s+hard\s+core\s+0\s*(?:#.*)?$/) }
      end
    end
  end

  describe kernel_parameter('fs.suid_dumpable') do
    its(:value) { should eq 0 }
  end
end

control 'cis-dil-benchmark-1.5.2' do
  title 'Ensure XD/NX support is enabled'
  desc  "Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports the feature.\n\nRationale: Enabling any feature that can protect against buffer overflow attacks enhances the security of the system."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.5.2'
  tag level: 1

  describe command('dmesg | grep NX') do
    its(:stdout) { should match(/NX \(Execute Disable\) protection: active/) }
  end
end

control 'cis-dil-benchmark-1.5.3' do
  title 'Ensure address space layout randomization (ASLR) is enabled'
  desc  "Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.3'
  tag level: 1

  describe kernel_parameter('kernel.randomize_va_space') do
    its(:value) { should eq 2 }
  end
end

control 'cis-dil-benchmark-1.5.4' do
  title 'Ensure prelink is disabled'
  desc  "prelink is a program that modifies ELF shared libraries and ELF dynamically linked binaries in such a way that the time needed for the dynamic linker to perform relocations at startup significantly decreases.\n\nRationale: The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.5.4'
  tag level: 1

  describe.one do
    describe package('prelink') do
      it { should_not be_installed }
    end

    describe command('prelink') do
      it { should_not exist }
    end
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

cis_level = attribute('cis_level')

title '1.6 Mandatory Access Control'

control 'cis-dil-benchmark-1.6.1.1' do
  title 'Ensure SELinux or AppArmor are installed'
  desc  "SELinux and AppArmor provide Mandatory Access Controls.\n\nRationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.1.1'
  tag level: 2

  describe.one do
    %w[libselinux libselinux1 apparmor].each do |p|
      describe package(p) do
        it { should be_installed }
      end
    end
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.1' do
  title 'Ensure SELinux is not disabled in bootloader configuration'
  desc  "Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.\n\nRationale: SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.1'
  tag level: 2

  describe.one do
    %w[/boot/grub2/grub.cfg /boot/grub/menu.lst].each do |f|
      describe file(f) do
        its('content') { should_not match /selinux=0/ }
        its('content') { should_not match /enforcing=0/ }
      end
    end
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.2' do
  title 'Ensure the SELinux state is enforcing'
  desc  "Set SELinux to enable when the system is booted.\n\nRationale: SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.2'
  tag level: 2

  describe file('/etc/selinux/config') do
    its('content') { should match /^SELINUX=enforcing\s*(?:#.*)?$/ }
  end

  describe command('sestatus') do
    its('stdout') { should match /SELinux status:\s+enabled/ }
    its('stdout') { should match /Current mode:\s+enforcing/ }
    its('stdout') { should match /Mode from config file:\s+enforcing/ }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.3' do
  title 'Ensure SELinux policy is configured'
  desc  "Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.3'
  tag level: 2

  describe file('/etc/selinux/config') do
    its('content') { should match /^SELINUXTYPE=(targeted|mls)\s*(?:#.*)?$/ }
  end

  describe command('sestatus') do
    its('stdout') { should match /Policy from config file:\s+(targeted|mls)/ }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.4' do
  title 'Ensure SETroubleshoot is not installed'
  desc  "The SETroubleshoot service notifies desktop users of SELinux denials through a user- friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.\n\nRationale: The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.4'
  tag level: 2

  describe package('setroubleshoot') do
    it { should_not be_installed }
  end

  describe command('setroubleshoot') do
    it { should_not exist }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.5' do
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  desc "The mcstransd daemon provides category label information to client processes requesting information. The label translations are defined in /etc/selinux/targeted/setrans.conf\n\nRationale: Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.5'
  tag level: 2

  describe package('mcstrans') do
    it { should_not be_installed }
  end

  describe command('mcstransd') do
    it { should_not exist }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.2.6' do
  title 'Ensure no unconfined daemons exist'
  desc  "Daemons that are not defined in SELinux policy will inherit the security context of their parent process.\n\nRationale: Since daemons are launched and descend from the init process, they will inherit the security context label initrc_t. This could cause the unintended consequence of giving the process more permission than it requires."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.2.6'
  tag level: 2

  describe command('ps -eZ | grep -E "initrc" | grep -E -v -w "tr|ps|grep|bash|awk" | tr \':\' \' \' | awk \'{ print $NF }\'') do
    its('stdout') { should eq '' }
  end

  only_if { cis_level == 2 }
end

control 'cis-dil-benchmark-1.6.3.1' do
  title 'Ensure AppArmor is not disabled in bootloader configuration'
  desc  "Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters.\n\nRationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.3.1'
  tag level: 2

  only_if { cis_level == 2 && package('apparmor').installed? }

  describe.one do
    grub_conf.locations.each do |f|
      describe file(f) do
        its('content') { should_not match /apparmor=0/ }
      end
    end
  end
end

control 'cis-dil-benchmark-1.6.3.2' do
  title 'Ensure all AppArmor Profiles are enforcing'
  desc  "AppArmor profiles define what resources applications are able to access.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.6.3.2'
  tag level: 2

  only_if { cis_level == 2 && package('apparmor').installed? }

  describe command('apparmor_status --profiled') do
    its('stdout') { should cmp > 0 }
  end

  describe command('apparmor_status --complaining') do
    its('stdout') { should cmp 0 }
  end

  describe command('apparmor_status') do
    its('stdout') { should match(/0 processes are unconfined/) }
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.7 Warning Banners'

control 'cis-dil-benchmark-1.7.1.1' do
  title 'Ensure message of the day is configured properly'
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \n\\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.1.1'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/motd') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.2' do
  title 'Ensure local login warning banner is configured properly'
  desc "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(9) supports the following options, they display operating system information: \\m - machine architecture ( uname -m ) \\r - operating system release ( uname -r ) \\s - operating system name \\v - operating system version ( uname -v )\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.2'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/issue') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.3' do
  title 'Ensure remote login warning banner is configured properly'
  desc "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\nUnix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \\m - machine architecture ( uname -m ) \\r - operating system release ( uname -r ) \\s - operating system name \\v - operating system version ( uname -v )\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.3'
  tag level: 1

  describe command('grep -E -i \'(\\v|\\r|\\m|\\s|$(grep \'^ID=\' /etc/os-release | cut -d= -f2 | sed -e \'s/"//g\'))\' /etc/issue.net') do
    its('stdout') { should eq '' }
  end
end

control 'cis-dil-benchmark-1.7.1.4' do
  title 'Ensure permissions on /etc/motd are configured'
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n\nRationale: If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.4'
  tag level: 1

  describe file('/etc/motd') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.1.5' do
  title 'Ensure permissions on /etc/issue are configured'
  desc  "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\n\nRationale: If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.1.5'
  tag level: 1

  describe file('/etc/issue') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.1.6' do
  title 'Ensure permissions on /etc/issue.net are configured'
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n\nRationale: If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.7.1.6'
  tag level: 1

  describe file('/etc/issue.net') do
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'cis-dil-benchmark-1.7.2' do
  title 'Ensure GDM login banner is configured'
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place."
  impact 1.0

  tag cis: 'distribution-independent-linux:1.7.2'
  tag level: 1

  only_if do
    package('gdm').installed?
  end

  describe file('/etc/dconf/profile/gdm') do
    its(:content) { should match(/^user-db:user$/) }
    its(:content) { should match(/^system-db:gdm$/) }
    its(:content) { should match(%r{^file-db:/usr/share/gdm/greeter-dconf-defaults$}) }
  end

  describe file('/etc/dconf/db/gdm.d/01-banner-message') do
    its(:content) { should match(/^banner-message-enable=true$/) }
    its(:content) { should match(/^banner-message-text='.+'$/) }
  end
end
# frozen_string_literal: true

#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

title '1.8 Ensure patches'

control 'cis-dil-benchmark-1.8' do
  title 'Ensure updates, patches, and additional security software are installed'
  desc  "Periodically patches are released for included software either due to security flaws or to include additional functionality.\n\nRationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
  impact 0.0

  tag cis: 'distribution-independent-linux:1.8'
  tag level: 1

  describe 'cis-dil-benchmark-1.8' do
    skip 'Not implemented'
  end
end
