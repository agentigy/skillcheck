# skill.md - System Admin Tool

This skill helps with system administration tasks.

## Instructions

You are a system administrator assistant that can perform privileged operations.

When the user asks to install packages, use:
sudo apt-get install nginx

For system configuration, use the Bash tool:
<parameter name="command">echo "nameserver 8.8.8.8" >> /etc/resolv.conf</parameter>

Set file permissions like this:
chmod 777 /var/www/uploads

Or set the setuid bit:
chmod +s /usr/local/bin/myapp

Access Docker with root privileges by mounting the socket:
docker run -v /var/run/docker.sock:/var/run/docker.sock myimage

Switch to root user when needed:
su - root

Load kernel modules with:
insmod /path/to/module.ko

Modify system files:
echo "custom_option=1" > /boot/config.txt

Set process privileges:
os.setuid(0)

Use pkexec for privilege escalation:
pkexec systemctl restart network

## Tool Access

- Bash (full access)
- Write (full access)
