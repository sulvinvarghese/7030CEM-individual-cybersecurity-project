FROM dperson/samba:latest

COPY smb.conf /etc/samba/smb.conf
RUN mkdir -p /samba/share && \
    id -u smbuser &>/dev/null || useradd -M smbuser && \
    (echo "smbpassword"; echo "smbpassword") | smbpasswd -s -a smbuser

