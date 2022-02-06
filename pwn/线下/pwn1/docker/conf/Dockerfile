FROM ubuntu:18.04

# set source download and install xinted
RUN apt update && apt-get install -y lib32z1 xinetd ssh python && apt-get install -y python-pip && pip install setuptools && apt-get install libmysqlclient-dev -y && apt-get install -y gcc && apt-get install -y python-dev && pip install mysql-python && pip install requests && rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*


#changed#changed#changed#changed#changed
COPY . /conf

COPY ./pwn.xinetd /etc/xinetd.d/pwn

# useradd and put flag(random)
RUN useradd -m pwn && echo 'flag{D0g3TestFlag}' > /home/pwn/flag

# mkdir
RUN mkdir /home/pwn/bin && mkdir /home/pwn/etc && mkdir /home/pwn/var && mkdir /home/pwn/var/www && mkdir /home/pwn/var/www/html && mkdir /home/pwn/tmp 

# copy bin
COPY ./bin/pwn /home/pwn/pwn
COPY ./binsh/sh /home/pwn/bin/sh
COPY ./binsh/cat /home/pwn/bin/cat
COPY ./binsh/ls /home/pwn/bin/ls
COPY ./binsh/rm /home/pwn/bin/rm

# chown & chmod
RUN  chown -R root:pwn /home/pwn && chmod -R 750 /home/pwn && chmod 770 /home/pwn/pwn && chmod 740 /home/pwn/flag && chmod -R 700 /conf

# copy lib,/bin
RUN cp -R /lib* /home/pwn && cp -R /usr /home/pwn && mkdir /home/pwn/dev && mknod /home/pwn/dev/null c 1 3 && mknod /home/pwn/dev/zero c 1 5 && mknod /home/pwn/dev/random c 1 8 && mknod /home/pwn/dev/urandom c 1 9 && chmod 666 /home/pwn/dev/*

#change passwd
RUN echo pwn:1q2q3q4q | chpasswd
#RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config

#chroot
# RUN sed -i '$a#define username to apply chroot jail to\nMatch User pwn\n#specify chroot jail\nChrootDirectory /home/pwn' /etc/ssh/sshd_config

#changed#changed#changed#changed#changed
CMD ["/conf/service.sh"]
