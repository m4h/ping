#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

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

  // create ipv4 header
  struct in_addr ip_aton;
  struct sockaddr_in ip_hdr;
  inet_aton(opts->ip, &ip_aton);
  memset(&ip_hdr, 0, sizeof(ip_hdr));
  ip_hdr.sin_family = AF_INET;
  ip_hdr.sin_addr = ip_aton;

  struct timeval timeout = {opts->timeout, 0};
  fd_set read_set;
  memset(&read_set, 0, sizeof(read_set));
  FD_SET(icmp_sock, &read_set);
  for (; opts->tries != 0; opts->tries--) {
    char icmp_pckt[opts->icmp_pckt_size];
    memset(&icmp_pckt, 0, sizeof(icmp_pckt));

    // create icmp header
    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = opts->icmp_type;
    icmp_hdr.un.echo.sequence = htons(opts->icmp_sequence++);
    icmp_hdr.un.echo.id = htons(opts->icmp_idi);
    icmp_hdr.checksum = 0;

    // create icmp packet (header + payload)
    memcpy(icmp_pckt, &icmp_hdr, sizeof(icmp_hdr));
    memcpy(icmp_pckt + sizeof(icmp_hdr), opts->icmp_payl, strlen(opts->icmp_payl));
    int icmp_pckt_len = sizeof(icmp_hdr) + strlen(opts->icmp_payl);
    uint16_t csum = icmp_csum((uint16_t*)&icmp_pckt, icmp_pckt_len);
    icmp_hdr.checksum = csum;
    memcpy(icmp_pckt, &icmp_hdr, sizeof(icmp_hdr));

    // send packet over wire
    int rc = 0;
    rc = sendto(icmp_sock, icmp_pckt, icmp_pckt_len, 0, (struct sockaddr*)&ip_hdr, sizeof(ip_hdr));
    if (rc <= 0) {
      printf("error: failed to send icmp packet. errno: %d\n", errno);
      return errno;
    }

    rc = select(icmp_sock + 1, &read_set, NULL, NULL, &timeout);
    if (rc == 0) {
      printf("error: timeout\n");
    } else if (rc == -1) {
      printf("error: failed to read icmp packet. errno:%d\n", errno);
    }

    char icmp_pckt_rcv[opts->icmp_pckt_size];
    struct icmphdr icmp_hdr_rcv;
    memset(icmp_pckt_rcv, 0, sizeof(icmp_pckt_rcv));
    memset(&icmp_hdr_rcv, 0, sizeof(icmp_hdr_rcv));

    rc = recvfrom(icmp_sock, icmp_pckt_rcv, sizeof(icmp_pckt_rcv), 0, NULL, NULL);
    if (rc == 0) {
      printf("error: icmp connection was reset\n");
    } else if (rc == -1) {
      printf("error: icmp connection was interrupted. errno:%d\n", errno);
    } else if (rc < (int)sizeof(icmp_hdr_rcv)) {
      printf("error: got packet shorter than header\n");
    } else {
      memcpy(&icmp_hdr_rcv, icmp_pckt_rcv, sizeof(icmp_hdr_rcv));
      if (icmp_hdr_rcv.type == ICMP_ECHOREPLY) {
        printf("recv seq %d\n", icmp_hdr_rcv.un.echo.sequence);
      } else {
        printf("recv icmp packet with wrong type : %d\n", icmp_hdr_rcv.type);
      }
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
  opts.interval = 1;
  opts.timeout = 1;

  do_icmp(&opts);

  return errno;
}
