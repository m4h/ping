#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <time.h>

/*
  gcc main.c -o p; sudo chown root:root p; sudo chmod ugo+rxs p

  - server uptime by tsval
  - account information for statistic
  - visual display of packets

  FIXME: timeout issue (actually timeout doesn't work as expected)
*/

struct cmd_opts {
  const char    *ip;
  uint16_t      icmp_type;
  uint32_t      icmp_idi;
  uint32_t      icmp_sequence;
  uint32_t      icmp_len;
  char          *icmp_payload;
  int           packets;
  float         interval;
  int           timeout;
  // FIXME: min_ttl, max_ttl
  unsigned char ttl;
  double        max_rtt;
  double        min_rtt;
};

struct accounting {
  float max_ms;
  float min_ms;
  float tot_ms;
  long  packets;
};

uint16_t icmp_csum(uint16_t *h, uint32_t l)
{
  unsigned long csum = 0;
  while (l > 1) {
    csum += *h++;
    l -= sizeof(unsigned short);
  }
  if (l) {
    csum += *(unsigned char*)h;
  }
  csum = (csum >> 16) + (csum & 0xffff);
  csum += (csum >> 16);
  return (uint16_t)(~csum);
}


void do_display_errno(int e)
{
  switch(e) {
    case 101:
      printf("errno %d: network is unreachable\n", e);
      break;
    default:
      printf("errno: %d\n", e);
  }
}


void do_display_graph(struct accounting *s, struct cmd_opts *o, double rtt)
{
  if (s->packets == 1) {
    printf("--- rtt based graph: '!' is more than %.fms; '-' is less than %.fms; 't' is timeout (%ds) ---\n", o->max_rtt, o->min_rtt, o->timeout);
  }
  //FIXME: account max_rtt and min_rtt
  if (rtt == -1) {
    printf("t");
  } else if (rtt > o->max_rtt) {
    printf("!");
  } else if (rtt < o->min_rtt) {
    printf("-");
  } else {
    printf(".");
  }
  fflush(stdout);
  // jump to next line when - 60 chars were displayed or we displayed char for last packet
  if (((s->packets != 0) && (s->packets % 60) == 0) || (o->packets == 1)) {
    printf(" - line statistic\n");
  }
}


void do_display_summary(struct accounting *s)
{
  printf("--- statistics ---\n");
  printf("min rtt=%.1fms; max rtt=%.1fms; avg rtt=%.1fms\n", s->min_ms, s->max_ms, (s->tot_ms/s->packets));
}


int do_open_socket(struct cmd_opts *o)
{
  int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (s < 0) {
    printf("error: failed to open socket. errno: %d\n", errno);
    return -1;
  }
  // set TTL on IP packet 
  int rc = setsockopt(s, IPPROTO_IP, IP_TTL, &o->ttl, sizeof(o->ttl));
  if (rc != 0) {
    printf("error: failed to set ttl. errno: %d\n", errno);
    return -1;
  }
  return s;
}


// FIXME: pass buffer to hold icmp packet, after copy from internal buffer to arg buffer and release internal buffers
// the idea - each scope manage his own buffers and there are no pointers travel between functions
int do_send_icmp(int s, struct cmd_opts *o, void *p)
{
  // create ipv4 header
  struct in_addr ip_aton;
  struct sockaddr_in ip_hdr;
  inet_aton(o->ip, &ip_aton);
  memset(&ip_hdr, 0, sizeof(ip_hdr));
  ip_hdr.sin_family = AF_INET;
  ip_hdr.sin_addr = ip_aton;

  // create icmp header
  // icmp header length
  int hlen = sizeof(struct icmphdr);
  // phdr is used as icmp header buffer (sent and recv)
  struct icmphdr *phdr = malloc(hlen);
  if (phdr == NULL) {
    printf("error: failed to allocate %d bytes. errno: %d\n", hlen, errno);
    return -1;
  }
  memset(phdr, 0, hlen);
  phdr->type = o->icmp_type;
  phdr->un.echo.sequence = htons(o->icmp_sequence++);
  phdr->un.echo.id = htons(o->icmp_idi);
  phdr->checksum = 0;

  // create icmp packet (header + payload)
  // ppckt is used as icmp packet buffer (sent and recv)
  char *ppckt = malloc(o->icmp_len);
  if (ppckt == NULL) {
    printf("error: failed to allocate %d bytes. errno: %d\n", o->icmp_len, errno);
    return -1;
  }
  memset(ppckt, 0, o->icmp_len);
  // copy icmp header to packet buffer
  memcpy(ppckt, phdr, hlen);
  // copy icmp payload to packet buffer
  memcpy(ppckt + hlen, o->icmp_payload, strlen(o->icmp_payload));
  int plen = hlen + strlen(o->icmp_payload);
  uint16_t csum = icmp_csum((uint16_t*)ppckt, plen);
  phdr->checksum = csum;
  // copy icmp header with correct checksum
  memcpy(ppckt, phdr, hlen);
  
  // send packet over wire
  int rc = sendto(s, ppckt, plen, 0, (struct sockaddr*)&ip_hdr, sizeof(ip_hdr));
  // wait for response
  struct timeval tv = {o->timeout, 0};
  fd_set rfd;
  FD_ZERO(&rfd);
  FD_SET(s, &rfd);
  rc = select(s + 1, &rfd, NULL, NULL, &tv);
  if (rc == -1) {
    printf("error: failed to read icmp packet. errno:%d\n", errno);
    return -1;
  }
  // read response from socket and write to ppckt buffer
  memset(ppckt, 0, o->icmp_len);
  rc = recvfrom(s, ppckt, o->icmp_len, MSG_DONTWAIT, NULL, NULL);
  memcpy(p, ppckt, o->icmp_len);
  /*
  // since SOCK_RAW is used - ppckt will hold 20 bytes of ipv4 header
  memset(phdr, 0, hlen);
  memcpy(phdr, ppckt + 20, hlen);
  */
  if (ppckt != NULL) {
    free(ppckt);
  }
  return rc;
}


int do_icmp(struct cmd_opts *opts)
{
  int sockfd = do_open_socket(opts);
  // variables used to compute and store rtt (round trip time) value
  struct timespec tstart, tend;
  double rtt;
  // ttl (up to 256)
  unsigned char ttl;
  // accounting
  struct accounting stats;
  stats.min_ms = 65536;
  stats.tot_ms = 0;
  stats.packets = 0;

  for (; opts->packets != 0; opts->packets--) {
    // FIXME
    int hlen = sizeof(struct icmphdr);
    struct icmphdr *phdr = malloc(hlen);

    char *buf = malloc(sizeof(char) * opts->icmp_len);
    memset(buf, 0, opts->icmp_len);
    clock_gettime(CLOCK_REALTIME, &tstart);
    int rc = do_send_icmp(sockfd, opts, buf);
    
    if (rc == 0) {
      printf("error: icmp connection was reset\n");
      return -1;
    } else if (rc == -1) {
      // EAGAIN indicate that select(3) hit timeout and recvfrom(3) don't have data to read
      // FIXME: ugly stuff
      if (errno == EAGAIN) {
        // reset readfd and skip the packet
        /*
        free(phdr);
        free(ppckt);
        */
        // FIXME: packets++ is not correct as after calculation done on these packets. need to introduce chars variable
        stats.packets++;
        do_display_graph(&stats, opts, -1);
        continue;
      } else {
        printf("error: icmp connection was interrupted. errno:%d\n", errno);
        return errno;
      }
    } else if (rc < (int)sizeof(hlen)) {
      printf("error: got packet shorter than header\n");
      return errno;
    }
    clock_gettime(CLOCK_REALTIME, &tend);
    // rtt is stored in ms - hence we need to convert tv_sec and tv_nsec to ms
    rtt = (tend.tv_sec - tstart.tv_sec) * 1000.0;
    rtt += (tend.tv_nsec - tstart.tv_nsec) / 1000000.0;

    memset(phdr, 0, hlen);
    memcpy(phdr, buf + 20, hlen);
    memset(&ttl, 0, sizeof(unsigned char));
    // FIXME: rewrite ugly hack with 9th byte offset - get ttl from ip header (ttl is 9th byte)
    memcpy(&ttl, buf + 8, sizeof(unsigned char));

    // account statistic
    stats.packets++;
    stats.tot_ms += rtt;
    if (rtt > stats.max_ms) {
      stats.max_ms = rtt;
    }
    if (rtt < stats.min_ms) {
      stats.min_ms = rtt;
    }
    if (phdr->type == ICMP_ECHOREPLY) {
      printf("recv: seq=%d; time=%.1fms; ttl=%d\n", ntohs(phdr->un.echo.sequence), rtt, ttl);
      //do_display_graph(&stats, opts, rtt);
    } else {
      printf("recv: icmp packet with wrong type : %d\n", phdr->type);
    }

    if (phdr != NULL) {
      free(phdr);
      phdr = NULL;
    }
    if (buf != NULL) {
      free(buf);
      buf = NULL;
    }
    // FIXME: convert to nanosleep
    sleep(opts->interval);
  }
  do_display_summary(&stats);
  close(sockfd);
  return 0;
}


int main(int argc, char **argv)
{
  struct cmd_opts opts;
  opts.ip = argv[1];
  opts.icmp_type = ICMP_ECHO;
  opts.icmp_len = 4096;
  opts.icmp_sequence = 12;
  // FIXME: rename icmp_idi to something more intuitive
  opts.icmp_idi = getpid();
  opts.icmp_payload = "....";
  opts.packets = atoi(argv[2]);
  opts.interval = 1;
  opts.timeout = 1;
  opts.ttl = 28;
  opts.max_rtt = 100;
  opts.min_rtt = 1;

  int rc = do_icmp(&opts);

  return rc;
}
