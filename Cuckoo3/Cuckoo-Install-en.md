# Cuckoo3-cert-ee Install Ubuntu 22.04

Sources :
 - **https://github.com/cert-ee/cuckoo3**
 - **https://reversingfun.com/posts/cuckoo-3-installation-guide/**

Minimum Requirements: An Ubuntu Jammy host with a Windows 10 VM as a sandbox.
Maximum Requirements: Ubuntu Jammy host with your desired components.

For security reasons, we will only install official repositories, making the process a bit more challenging.
## I- Requierements

I use a Proxmox environment, allowing me to manipulate hardware as needed. Based on my experience, here are the minimum required resources:

- Windows 7 with SP1. Build 1706
- Windows 10. Build 1703

You can download official ISOs for Cuckoo3 developers [here](https://github.com/cert-ee/cuckoo3/blob/main/docs/src/installation/vmcreation.md#windows).

We will only consider one Windows 10 VM.

- Ubuntu 22.04 server
- 2 cpu
- 4 Go de ram
- 80 Go de disque

For a more robust setup (with 2 Windows 7 and Windows 10 VMs and multiple snapshots):

- Ubuntu 22.04 server
- 4 cpu
- 16 Go de ram
- 300 Go de disque

**(Optional)<!> To avoid errors, add an audio card to this host (functional or not, it doesn't matter).**

## II - Installation

Let's start by creating a cuckoo user and granting sudo privileges. Choose a password.

```
sudo adduser cuckoo
sudo gpasswd -a cuckoo sudo
```

Next, add the official deadsnake repository to retrieve all Python packages that are no longer referenced, and then install all dependencies:

```
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt install git build-essential python3.8 python3.8-dev python3.8-venv libhyperscan5 libhyperscan-dev libjpeg8-dev zlib1g-dev unzip p7zip-full rar unace-nonfree cabextract yara tcpdump genisoimage qemu-system-x86 qemu-utils qemu-system-common alsa-utils -y
```
Add the cuckoo user to the kvm and pcap groups:

```
sudo adduser cuckoo kvm
sudo chmod 666 /dev/kvm

sudo groupadd pcap
sudo adduser cuckoo pcap
```
Change the group of tcpdump to make it usable by cuckoo via the pcap group:
```
sudo chgrp pcap /usr/bin/tcpdump

sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

sudo ln -s /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/disable/usr.bin.tcpdump

sudo apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump
```
We'll need to connect and change the owner of /opt:

```
sudo chown cuckoo /opt && sudo chmod 777 /opt && cd /opt
su cukoo
```

Clone the cuckoo3 repository:

```
git clone https://github.com/cert-ee/cuckoo3
cd cuckoo3
```
Create a virtual environment for our manipulations:

```
python3 -m venv venv
source venv/bin/activate
```

Finally, we can install cuckoo3. This may take some time:
```
pip install whell

./install.sh
```
Successively create the Cuckoo configuration folder and install the signatures:

```
cuckoo createcwd

cuckoo getmonitor monitor.zip

unzip signatures.zip -d ~/.cuckoocwd/signatures/cuckoo/
```

Install vmcloak, which allows us to deploy virtual machines and snapshots for Cuckoo3:

```
git clone https://github.com/hatching/vmcloak.git && cd vmcloak
pip install . && cd ..
```
Create the result interface to receive and communicate analysis results:

```
sudo /opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24

sudo mkdir -p /etc/qemu
echo 'allow br0' | sudo tee /etc/qemu/bridge.conf

sudo chmod u+s /usr/lib/qemu/qemu-bridge-helper
```

(Optional) We can directly download the Windows 10 and Windows 7 ISOs:

```
vmcloak isodownload --win7x64 --download-to ~/win7x64.iso
vmcloak isodownload --win10x64 --download-to ~/win10x64.iso
```
Alternatively, retrieve your ISO (e.g., win10x64.iso). Mount the disk to use it as a base for our virtual machine:
```
sudo mkdir /mnt/win10x64
sudo mount -o loop,ro /home/cuckoo/win10x64.iso /mnt/win10x64
```
It turns out that vmcloak is not compatible with the latest versions of QEMU (two options in question: soundhw is no longer supported, and the backing file -b option adds the necessary format). [Source](https://github.com/hatching/vmcloak/issues/201) of the solution. Here's a corrected version of qemu.py to avoid errors. Replace all:

```
sudo nano /opt/cuckoo3/venv/lib/python3.8/site-packages/vmcloak/platforms/qemu.py
```
With :
```
# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of VMCloak - http://www.vmcloak.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

import logging
import os.path
import subprocess
import time
import shutil
from re import search
from pkg_resources import parse_version

from vmcloak.platforms import Machinery
from vmcloak.repository import vms_path, IPNet
from vmcloak.rand import random_vendor_mac
from vmcloak.machineconf import MachineConfDump
from vmcloak.ostype import get_os

log = logging.getLogger(__name__)
name = "QEMU"
disk_format = "qcow2"

machines = {}
confdumps = {}

default_net = IPNet("192.168.30.0/24")

QEMU_AMD64 = ["qemu-system-x86_64", "-monitor", "stdio"]

def _create_image_disk(path, size):
    log.info("Creating disk %s with size %s", path, size)
    subprocess.check_call(
        ["qemu-img", "create", "-f", "qcow2",
         "-o", "lazy_refcounts=on,cluster_size=2M", path, size]
    )

def _create_snapshot_disk(image_path, path):
    log.info("Creating snapshot %s with master %s", path, image_path)
    subprocess.check_call(["qemu-img", "create", "-F", "qcow2", "-o",
                           "lazy_refcounts=on,cluster_size=2M", "-b",
                           image_path, "-f", "qcow2", path])


def _make_pre_v41_args(attr):
    return [
        "-M", "q35",
        "-nodefaults",
        "-vga", "std",
        "-rtc", "base=localtime,driftfix=slew",
        "-realtime", "mlock=off",
        "-m", f"{attr['ramsize']}",
        "-smp", f"{attr['cpus']}",
        "-netdev", f"type=bridge,br={attr['adapter']},id=net0",
        "-device", f"rtl8139,netdev=net0,mac={attr['mac']},bus=pcie.0,addr=3",

        "-device", "ich9-ahci,id=ahci",
        "-device", "ide-drive,bus=ahci.0,unit=0,drive=disk,bootindex=2",
        "-device", "ide-cd,bus=ahci.1,unit=0,drive=cdrom,bootindex=1",
        "-device", "usb-ehci,id=ehci",
        "-device", "usb-tablet,bus=ehci.0",
         "-device", "intel-hda",
        "--enable-kvm"
    ]

# From 4.1 the -realtime mlock=off and -device ide-drive
# are deprecated and those are removed in higher versions.
def _make_post_v41_args(attr):
    return [
        "-nodefaults",
        "-M", "q35",
        "-vga", "std",
        "-smp", f"{attr['cpus']}",
        "-overcommit", "mem-lock=off",
        "-rtc", "base=localtime,driftfix=slew",
        "-m", f"{attr['ramsize']}",
        "-netdev", f"type=bridge,br={attr['adapter']},id=net0",
        "-device", f"rtl8139,netdev=net0,mac={attr['mac']},bus=pcie.0,addr=3",

        "-device", "ich9-ahci,id=ahci",
        "-device", "ide-hd,bus=ahci.0,unit=0,drive=disk,bootindex=2",

        "-device", "ide-cd,bus=ahci.1,unit=0,drive=cdrom,bootindex=1",
        "-device", "usb-ehci,id=ehci",
        "-device", "usb-tablet,bus=ehci.0",
        "-device", "intel-hda",
        "-enable-kvm"
    ]

def _make_args(attr, disk_placeholder=False, iso=None, display=None):

    if version() < parse_version("4.1"):
        args = _make_pre_v41_args(attr)
    else:
        args = _make_post_v41_args(attr)

    if iso:
        args.extend(["-drive", f"{iso}if=none,id=cdrom,readonly=on"])
    else:
        args.extend(["-drive", "if=none,id=cdrom,readonly=on"])

    if disk_placeholder:
        args.extend(
            ["-drive",
             "file=%DISPOSABLE_DISK_PATH%,format=qcow2,if=none,id=disk"]
        )
    else:
        args.extend(
            ["-drive",
             f"file={attr['path']},format=qcow2,if=none,id=disk"]
        )

    if display:
        args.extend(["-display", "gtk"])
    else:
        args.extend(["-display", "none"])

    return args


def _create_vm(name, attr, iso_path=None, is_snapshot=False):
    log.info("Create VM instance for %s", name)
    if not os.path.exists(attr["path"]):
        # We assume the caller has already checked if existing files are a
        # problem
        if is_snapshot:
            _create_snapshot_disk(attr["imgpath"], attr["path"])
        else:
            _create_image_disk(attr["path"], "%sG" % attr["hddsize"])

    net = attr["adapter"] or "br0"
    attr["adapter"] = net
    if iso_path:
        iso = "file=%s,format=raw," % iso_path
    else:
        iso = ""

    if not attr.get("mac") or is_snapshot:
        attr["mac"] = random_vendor_mac()

    if is_snapshot:
        os_helper = get_os(attr["osversion"])
        confdumps[name] = MachineConfDump(
            name=name, ip=attr["ip"], agent_port=attr["port"],
            os_name=os_helper.os_name, os_version=os_helper.os_version,
            architecture=os_helper.arch, bridge=net, mac=attr["mac"],
            gateway=attr["gateway"], netmask=attr["netmask"],
            disk=os.path.basename(attr["path"]),
            start_args=_make_args(attr, disk_placeholder=True)
        )
        confdumps[name].machinery_version = str(version())
        confdumps[name].machinery = "qemu"

    args = QEMU_AMD64 + _make_args(
        attr, disk_placeholder=False, iso=iso, display=attr.get("vm_visible")
    )
    if attr.get("vrde"):
        # Note that qemu will add 5900 to the port number
        port = attr["vrde"]
        args.extend(["-vnc", "0.0.0.0:%s" % port])

    log.debug("Execute: %s", " ".join(args))
    m = subprocess.Popen(args, stdin=subprocess.PIPE)
    machines[name] = m
    return m

#
# Platform API
#

def _get_vm_dir(vm_name):
    dirpath = os.path.join(vms_path, "qemu", vm_name)
    os.makedirs(dirpath, exist_ok=True, mode=0o775)
    return dirpath

def prepare_snapshot(name, attr):
    # Snapshots are stored in-line
    vm_dir = _get_vm_dir(name)
    path = os.path.join(vm_dir, f"disk.{disk_format}")
    attr["path"] = path
    if os.path.exists(path):
        return False

    return vm_dir

def create_new_image(name, _, iso_path, attr):
    if os.path.exists(attr["path"]):
        raise ValueError("Image %s already exists" % attr["path"])

    m = _create_vm(name, attr, iso_path=iso_path)
    m.wait()
    if m.returncode != 0:
        raise ValueError(m.returncode)

def create_snapshot_vm(image, name, attr):
    if os.path.exists(attr["path"]):
        raise ValueError("Snapshot %s already exists" % attr["path"])

    _create_vm(name, attr, is_snapshot=True)

_DECOMPRESS_BINARIES = {
    "lz4": shutil.which("lz4"),
    "gzip": shutil.which("gzip")
}

_DECOMPRESS_COMMANDS = {
    "lz4": "-z > %SNAPSHOT_PATH%",
    "gzip": "-c -3 > %SNAPSHOT_PATH%"
}

def _get_exec_args(memsnapshot_path):
    for tool in ("lz4", "gzip"):
        binary = _DECOMPRESS_BINARIES.get(tool)
        if binary:
            args = _DECOMPRESS_COMMANDS[tool].replace(
                "%SNAPSHOT_PATH%", memsnapshot_path
            )
            return f"{binary} {args}"

    return f"/bin/cat > {memsnapshot_path}"


MEMORY_SNAPSHOT_NAME = "memory.snapshot"
def create_snapshot(name):
    m = machines[name]
    snapshot_path = os.path.join(_get_vm_dir(name), MEMORY_SNAPSHOT_NAME)
    confdumps[name].add_machine_field("memory_snapshot", MEMORY_SNAPSHOT_NAME)
    # Stop the machine so the memory does not change while making the
    # memory snapshot.
    m.stdin.write(b"stop\n")
    m.stdin.write(b"migrate_set_speed 1G\n")
    # Send the actual memory snapshot command. The args helper tries to find
    # lz4 of gzip binaries so we can compress the dump.
    m.stdin.write(
        f"migrate \"exec:{_get_exec_args(snapshot_path)}\"\n".encode()
    )
    m.stdin.write(b"quit\n")
    log.debug("Flushing snapshot commands to qemu.")
    m.stdin.flush()
    m.wait()

def create_machineinfo_dump(name, image):
    confdump = confdumps[name]
    confdump.tags_from_image(image)
    dump_path = os.path.join(_get_vm_dir(name), confdump.DEFAULT_NAME)
    confdump.write_dump(dump_path)

def start_image_vm(image, user_attr=None):
    """Start transient VM"""
    attr = image.attr()
    if user_attr:
        attr.update(user_attr)
    _create_vm(image.name, attr)

def remove_vm_data(name):
    """Remove VM definitions and snapshots but keep disk image intact"""
    m = machines.get(name)
    if m:
        log.info("Cleanup VM %s", name)
        try:
            if m.returncode is None:
                m.kill()
        except OSError:
            pass
    else:
        log.info("Not running: %s", name)
    path = os.path.join(vms_path, "%s.%s" % (name, disk_format))
    if os.path.exists(path):
        os.remove(path)

def wait_for_shutdown(name, timeout=None):
    # TODO: timeout
    m = machines.get(name)
    end = None
    if timeout:
        end = time.time() + timeout
    while True:
        m.poll()
        if m.returncode is not None:
            if m.returncode == 0:
                return True
            raise ValueError(f"Non-zero exit code: {m.returncode}")
        if end and time.time() > end:
            raise ValueError("Timeout")
        time.sleep(1)

def clone_disk(image, target):
    log.info("Cloning disk %s to %s", image.path, target)
    shutil.copy(image.path, target)

def export_vm(image, target):
    raise NotImplementedError

def restore_snapshot(name, snap_name):
    path = os.path.join(_get_vm_dir(name), f"disk.{disk_format}")
    subprocess.check_call(["qemu-img", "snapshot", "-a", snap_name, path])

def remove_hd(path):
    os.remove(path)


def version():
    """Get the QEMU version qemu in PATH. Returns a
    version object from pkg_resources.parse_version if a version is found.
    passes empty string to parse_version if no version could be determined and
    returns result"""
    vdata = subprocess.check_output(["qemu-system-x86_64", "--version"])
    # Read QEMU version as if it were semver. It is not, but looks similar.
    version_r = (
        br"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*"
        br"[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-]"
        br"[0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"
    )

    match = search(version_r, vdata)
    if not match:
        return parse_version("")

    return parse_version(match.group().strip().decode())

#
# Helper class for dependencies
#

class VM(Machinery):
    def attach_iso(self, iso_path):
        m = machines.get(self.name)
        if not m:
            raise KeyError(
                "Cannot attach ISO to machine. Process handle not available."
            )

        m.stdin.write(f"change cdrom {iso_path}\n".encode())
        m.stdin.flush()

    def detach_iso(self):
        m = machines.get(self.name)
        if not m:
            raise KeyError(
                "Cannot attach ISO to machine. Process handle not available."
            )
        m.stdin.write(b"eject cdrom\n")
        m.stdin.flush()
```
(Example for Windows 10 here)

Create the base of the disk with our previously mounted ISO (this may take some time):

```
vmcloak --debug init --win10x64 --hddsize 30 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.2 --iso-mount /mnt/win10x64 win10base br0
```

Install the basic dependencies:
```
vmcloak --debug install win10base dotnet:4.7.2 java:7u80 vcredist:2013 vcredist:2019 edge carootcert wallpaper disableservices
```

Finally, create one or more snapshots once everything is initialized.
**You can create as many snapshots as needed depending on performance:**

```
vmcloak --debug snapshot --count 1 win10base win10vm_ 192.168.30.20
```

For Windows 7:
```
vmcloak isodownload --win7x64 --download-to ~/win7x64.iso
sudo mkdir /mnt/win7x64
sudo mount -o loop,ro /home/cuckoo/win7x64.iso /mnt/win7x64
vmcloak --debug init --win7x64 --hddsize 128 --cpus 2 --ramsize 4096 --network 192.168.30.0/24 --vm qemu --ip 192.168.30.3 --iso-mount /mnt/win7x64 win7base br0
vmcloak --debug install win7base dotnet:4.7.2 java:7u80 vcredist:2013 vcredist:2019 edge carootcert wallpaper disableservices
vmcloak --debug snapshot --count 5 win7base win7vm_ 192.168.30.30
```

Finally, import and migrate the virtual machine into Cuckoo:

```
cuckoo machine import qemu ~/.vmcloak/vms/qemu

cuckoo machine delete qemu example1

cuckoomigrate database all
```
Configure Cuckoo:
```
nano ~/.cuckoocwd/conf/cuckoo.yaml
```
```
 # listen IP and port. Make sure the IP is off a network interface that is part of the analysis machine network or
 # route/forward traffic between the analysis machines and the resultserver.
 resultserver:
-  listen_ip: 192.168.30.101
+  listen_ip: 0.0.0.0
   listen_port: 2042
# Settings used by Cuckoo to find the tcpdump binary to use for network capture of machine traffic.
tcpdump:
  enabled: True
-  path: /usr/sbin/tcpdump
+  path: /usr/bin/tcpdump
```
(Optional) Activate the modules: ~/.cuckoocwd/conf/processing/misp.yaml
```
 # Enable the usage of MISP queries in pre and post  processing for
 # the discovered IOCs.
- enabled: False
+ enabled: True

 # The MISP API url. Is also used as the base URL for creating links to
 # events.
- url: null
+ url: <your_misp_url>

 # Verify if the configured MISP server is using a valid TLS certificate.
 # Disable this your certificate is self-signed or no certificate is used.
verify_tls: True

 # The API key to access the MISP api.
- key: null
+ key: <misp_api_key>
Enabling VirusTotal 
Optionally add your VT API key to file ~/.cuckoocwd/conf/processing/virustotal.yaml

 # The VirusTotal API key to use. The default API key, kindly provided
 # by the VirusTotal team, should enable you with a sufficient throughput
 # and while being shared with all our users, it should not affect your use.
- key: a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088
+ key: <vt_api_key>
```
Finally, we can launch Cuckoo in debug mode to identify any potential errors:
```
cuckoo --debug
```

Cuckoo web :
```
cuckoo web --host 0.0.0.0 --port 8080
```
## III - Creation des Services

```
mkdir /opt/auto
nano /opt/auto/script_cuckoo_web.sh
```
Create the script to change the password with the cuckoo user's password.
```
#!/bin/bash
echo 'passusercuckoo' | sudo -S /opt/cuckoo3/venv/bin/vmcloak-qemubridge br0 192.168.30.1/24
source /opt/cuckoo3/venv/bin/activate
cuckoo web --host 0.0.0.0 --port 8080
```
Create the services:
```
sudo chmod +x /opt/auto/script_cuckoo_web.sh
sudo nano /etc/systemd/system/cuckoo-web.service
```

```
[Unit]
Description=Demarrage de Cuckoo-web
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/bash /opt/auto/script_cuckoo_web.sh
User=cuckoo
Group=cuckoo
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
For cuckoo-run :
```
nano /opt/auto/script_cuckoo_run.sh
```
```
#!/bin/bash
source /opt/cuckoo3/venv/bin/activate
cuckoo --debug
```
```
sudo chmod +x /opt/auto/script_cuckoo_run.sh
sudo nano /etc/systemd/system/cuckoo.service
```
Create the services:
```
[Unit]
Description=Demarrage de Cuckoo
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sleep 10
ExecStart=/usr/bin/bash /opt/auto/script_cuckoo_run.sh
User=cuckoo
Group=cuckoo
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
Activate and start:

```
sudo systemctl enable /etc/systemd/system/cuckoo-web.service && sudo systemctl start cuckoo-web.service

sudo systemctl enable /etc/systemd/system/cuckoo.service && sudo systemctl start cuckoo.service
```
Cuckoo and Cuckoo-web will be launched at startup.

##### Rààtus
##### 09/23