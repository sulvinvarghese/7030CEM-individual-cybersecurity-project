FROM debian:latest
RUN apt-get update && apt-get install -y iputils-ping curl
COPY generate_real_traffic.sh /usr/local/bin/generate_real_traffic.sh
RUN chmod +x /usr/local/bin/generate_real_traffic.sh
CMD ["/usr/local/bin/generate_real_traffic.sh"]
