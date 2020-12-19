# Network stack on PCAP
Author: Zizheng Guo (Kindly credit me if it helps you:)

This is a course project of [Computer Networks](http://soar.group/CompNets/Fall18/). Its goal is to implement TCP, IP and Ethernet on top of the frame i/o interface provided by libpcap.

## Compile
```bash
mkdir build
cd build
cmake ..
make
```

<!--

## Tips
I wrote some useful scripts outside this repo.

Insert this snippet into `~/.bashrc`, and the name of the current network namespace will be put before every prompt in bash.

``` shell
netns=$(ip netns identify)
if [ "$netns" = "" ]; then
    netns_prompt=""
else
    netns_prompt="($netns) "
fi

if [ "$color_prompt" = yes ]; then
    PS1='$netns_prompt${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='$netns_prompt${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt
```
-->

