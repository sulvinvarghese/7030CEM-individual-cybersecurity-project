FROM fauria/vsftpd:latest

COPY vsftpd.conf /etc/vsftpd.conf
RUN mkdir -p /var/run/vsftpd/empty /var/ftp

EXPOSE 21 21100-21110
CMD ["/usr/sbin/run-vsftpd.sh"]
