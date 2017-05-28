#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <poll.h>

/*
  gcc main.c -o p; sudo chown root:root p; sudo chmod ugo+rxs p
*/

struct cmd_opts {
  const char  *ip;
  uint16_t    icmp_type;
  uint32_t    icmp_idi;
  uint32_t    icmp_sequence;
  uint32_t    icmp_pckt_size;
  char        *icmp_payl;
  int         tries;
  float       interval;
  int         timeout;
};


uint16_t icmp_csum(uint16_t *hdr, uint32_t len)
{
  unsigned long csum = 0;
  while (len > 1) {
    csum += *hdr++;
    len -= sizeof(unsigned short);
  }
  if (len) {
    csum += *(unsigned char*)hdr;
  }
  csum = (csum >> 16) + (csum & 0xffff);
  csum += (csum >> 16);
  return (uint16_t)(~csum);
}


int do_icmp(struct cmd_opts *opts)
{
  int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (icmp_sock < 0) {
    printf("error: failed to open socket. errno: %d\n", errno);
    return errno;
  }

  struct in_addr ip_aton;
  struct sockaddr_in ip_hdr;
  inet_aton(opts->ip, &ip_aton);
  memset(&ip_hdr, 0, sizeof(ip_hdr));
  ip_hdr.sin_family = AF_INET;
  ip_hdr.sin_addr = ip_aton;

  for (; opts->tries != 0; opts->tries--) {
    char icmp_pckt[opts->icmp_pckt_size];
    memset(&icmp_pckt, 0, sizeof(icmp_pckt));

    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = opts->icmp_type;
    icmp_hdr.un.echo.sequence = htons(opts->icmp_sequence++);
    icmp_hdr.un.echo.id = htons(opts->icmp_idi);
    icmp_hdr.checksum = 0;

    memcpy(icmp_pckt, &icmp_hdr, sizeof(icmp_hdr));
    memcpy(icmp_pckt + sizeof(icmp_hdr), opts->icmp_payl, strlen(opts->icmp_payl));
    int icmp_pckt_len = sizeof(icmp_hdr) + strlen(opts->icmp_payl);
    uint16_t csum = icmp_csum((uint16_t*)&icmp_pckt, icmp_pckt_len);
    icmp_hdr.checksum = csum;
    memcpy(icmp_pckt, &icmp_hdr, sizeof(icmp_hdr));

    int rc = 0;
    rc = sendto(icmp_sock, icmp_pckt, icmp_pckt_len, 0, (struct sockaddr*)&ip_hdr, sizeof(ip_hdr));
    if (rc <= 0) {
      printf("error: failed to send icmp packet. errno: %d\n", errno);
      return errno;
    }

    //rc = poll(icmp_pollfds, sizeof(icmp_pollfds), opts->timeout);
    rc = ppoll(icmp_pollfds, sizeof(icmp_pollfds), NULL, NULL);
    if (rc == 0) {
      printf("error: timeout\n");
    } else if (rc == -1) {
      printf("error: failed to read icmp packet. errno:%d\n", errno);
    }
    sleep(opts->interval);
  }
  return 0;

}


int main(int argc, char **argv)
{
  struct cmd_opts opts;
  opts.ip = argv[1];
  opts.icmp_type = ICMP_ECHO;
  opts.icmp_pckt_size = 4096;
  opts.icmp_sequence = 12;
  opts.icmp_idi = 1;
  opts.icmp_payl = "....";
  opts.tries = 3;
  opts.interval = 0;
  opts.timeout = 0.1;

  do_icmp(&opts);

  return errno;
}


int main0(int argc, char **argv) 
{
  struct icmphdr icmp_header;
  struct sockaddr_in address;
  struct in_addr addr_dst;

  if (inet_aton(argv[1], &addr_dst) == 0) {
    printf("error: invalid ip address\n");
    return -1;
  }

  int icmp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (icmp_sock < 0) {
    printf("error: failed to open socket. errno: %d\n", errno);
    return errno;
  }

  for(;;) {
  memset(&address, 0, sizeof address);
  address.sin_family = AF_INET;
  address.sin_addr = addr_dst;

  memset(&icmp_header, 0, sizeof icmp_header);
  icmp_header.type = ICMP_ECHO;
  // configurable
  unsigned char packet[1024];
  // configurable
  struct timeval timeout = {10, 0};
  fd_set read_set;
  socklen_t icmp_sock_len;
  struct icmphdr icmp_header_rcv;
  // configurable 
  uint16_t icmp_sequence = 1;
  struct timeval time_snt, time_rcv;
  long rttime = 0;
  // configurable
  char payload[] = "........................................................";
  size_t payload_len = strlen(payload);


  icmp_header.un.echo.sequence = htons(icmp_sequence++);
  memcpy(packet, &icmp_header, sizeof icmp_header);
  memcpy(packet + sizeof icmp_header, payload, payload_len);
  int was_sent;
  gettimeofday(&time_snt, NULL);
  was_sent = sendto(icmp_sock, packet, sizeof icmp_header + payload_len, 0, 
                    (struct sockaddr*)&address, sizeof address);
  if (was_sent <= 0) {
    printf("error: failed to sent icmp packet. errno: %d\n", errno);
    return errno;
  }

  memset(&read_set, 0, sizeof read_set);
  FD_SET(icmp_sock, &read_set);

  was_sent = select(icmp_sock + 1, &read_set, NULL, NULL, &timeout);
  if (was_sent == 0) {
    printf("error: icmp request timed out\n");
    return -1;
  } else if (was_sent < 0) {
    printf("error: failed to read from socket. errno: %d\n", errno);
    return errno;
  }

  icmp_sock_len = 0;
  was_sent = recvfrom(icmp_sock, packet, sizeof packet, 0, NULL, &icmp_sock_len);
  gettimeofday(&time_rcv, NULL);
  rttime = (long)(time_rcv.tv_usec - time_snt.tv_usec) / 1000 + (long)(time_rcv.tv_sec - time_snt.tv_sec);
  if (rttime < 0)
    rttime = rttime + 1000;
  if (was_sent <= 0) {
    printf("error: failed to receive. errno: %d\n", errno);
    return errno;
  } else if (was_sent < sizeof icmp_header_rcv) {
    printf("error: got short icmp header\n");
    return -1;
  }

  memcpy(&icmp_header_rcv, packet, sizeof icmp_header_rcv);
  if (icmp_header_rcv.type == ICMP_ECHOREPLY) {
    printf("icmp reply: time=%dms, id=0x%x, seq=0x%x\n",
           rttime,
           icmp_header_rcv.un.echo.id,
           icmp_header_rcv.un.echo.sequence);
  } else {
    printf("error: wrong icmp reply type: 0x%x\n", icmp_header_rcv.type);
  }
  // configurable
  sleep(1);
  }

  return 0;
}
