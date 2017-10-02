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
#include <argp.h>

/*
 * why need to use this:
 *  expose icmp packet options
 *  cool displays (json)
 *
 * structure of program:
 * main
 *  read options and set defaults
 *  loop
 *    send_packet
 *    display
 *      display_type
 *  display statistics
 *    display_type
 *
*/

/*
  gcc main.c -o p; sudo chown root:root p; sudo chmod ugo+rxs p

  - server uptime by tsval
  - account information for statistic
  - visual display of packets
  - display info by icmp->code (https://gist.github.com/kbaribeau/4495181)


  FIXME: timeout issue (actually timeout doesn't work as expected)
*/
const char *argp_program_version = "0.1";
const char *argp_program_bug_address = "<artyom.klimenko@gmail.com>";
static char args_doc[] = "DESTINATION";
static struct argp_option options[] = {
  {"count",   'c', "COUNT",   0, "packets count", 0},
  {0}
};

struct arguments
{
  char          *ip;            // ip address
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

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;
  switch(key) {
    case 'c':
      arguments->packets = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      arguments->ip = arg;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, 0, 0, 0, 0};

struct accounting {
  float max_ms;
  float min_ms;
  float tot_ms;
  long  packets;
};


uint16_t icmp_checksum(uint16_t *h, uint32_t l)
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


void *do_malloc(int len)
{
  void *ptr = malloc(len);
  if (ptr == NULL) {
    printf("error: failed to allocate %d bytes. errno: %d\n", len, errno);
    return ptr;
  }
  memset(ptr, 0, len);
  return ptr;
}

void do_free(void *ptr)
{
  if (ptr != NULL) {
    free(ptr);
    ptr = NULL;
  }
}

void do_display_graph(struct accounting *s, struct arguments *o, double rtt)
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
  //FIXME: display statistics on CTRL+C
  printf("--- statistics ---\n");
  printf("min rtt=%.1fms; max rtt=%.1fms; avg rtt=%.1fms\n", s->min_ms, s->max_ms, (s->tot_ms/s->packets));
}


int do_open_socket(struct arguments *options)
{
  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    printf("error: failed to open socket. errno: %d\n", errno);
    return -1;
  }
  // set TTL on IP packet 
  int rc = setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &options->ttl, sizeof(options->ttl));
  if (rc != 0) {
    printf("error: failed to set ttl. errno: %d\n", errno);
    return -1;
  }
  return socket_fd;
}


double do_timespec_delta(struct timespec s, struct timespec e)
{
  /* 
   * find delta in ms between two struct timespec
   * @s - start timespec
   * @e - end timespec (
   * return - delta in milliseconds
   */
  double ms = (e.tv_sec - s.tv_sec) * 1000.0;
  ms += (e.tv_nsec - s.tv_nsec) / 1000000.0;
  return ms;
}


int do_send_icmp(int socket_fd, struct arguments *options, void *packet)
{
  // create ipv4 header
  struct sockaddr_in ip_hdr;
  struct in_addr ip_addr;
  inet_aton(options->ip, &ip_addr);
  memset(&ip_hdr, 0, sizeof(ip_hdr));
  ip_hdr.sin_family = AF_INET;
  ip_hdr.sin_addr = ip_addr;

  // create icmp header
  int icmp_hdr_len = sizeof(struct icmphdr);
  // icmp_hdr_ptr is used as icmp header buffer (sent and recv)
  struct icmphdr *icmp_hdr_ptr = do_malloc(icmp_hdr_len);
  if (icmp_hdr_ptr == NULL) {
    return -1;
  }
  icmp_hdr_ptr->type = options->icmp_type;
  icmp_hdr_ptr->un.echo.sequence = htons(options->icmp_sequence++);
  icmp_hdr_ptr->un.echo.id = htons(options->icmp_idi);
  icmp_hdr_ptr->checksum = 0;

  // create icmp packet (header + payload)
  // packet_ptr is used as icmp packet buffer (sent and recv)
  char *packet_ptr = do_malloc(options->icmp_len);
  if (packet_ptr == NULL) {
    return -1;
  }
  // copy icmp header to packet buffer
  memcpy(packet_ptr, icmp_hdr_ptr, icmp_hdr_len);
  // copy icmp payload to packet buffer
  memcpy(packet_ptr + icmp_hdr_len, options->icmp_payload, strlen(options->icmp_payload));
  int packet_len = icmp_hdr_len + strlen(options->icmp_payload);
  uint16_t checksum = icmp_checksum((uint16_t*)packet_ptr, packet_len);
  icmp_hdr_ptr->checksum = checksum;
  // copy icmp header with correct checksum
  memcpy(packet_ptr, icmp_hdr_ptr, icmp_hdr_len);
  
  // send packet over wire
  sendto(socket_fd, packet_ptr, packet_len, 0, (struct sockaddr*)&ip_hdr, sizeof(ip_hdr));
  // wait for response
  struct timeval timeout = {options->timeout, 0};
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(socket_fd, &read_set);
  int rc = select(socket_fd + 1, &read_set, NULL, NULL, &timeout);
  if (rc == -1) {
    printf("error: failed to read icmp packet. errno:%d\n", errno);
    return -1;
  }
  // read response from socket and write to packet_ptr buffer
  memset(packet_ptr, 0, options->icmp_len);
  rc = recvfrom(socket_fd, packet_ptr, options->icmp_len, MSG_DONTWAIT, NULL, NULL);
  memcpy(packet, packet_ptr, options->icmp_len);
  do_free(icmp_hdr_ptr);
  do_free(packet_ptr);
  return rc;
}


int do_main_loop(struct arguments *options)
{
  double rtt;
  // variables used to compute and store rtt (round trip time) value
  struct timespec tstart, tend;
  // ttl (up to 256)
  unsigned char ttl;
  // accounting
  struct accounting stats;
  stats.min_ms = 65536;
  stats.tot_ms = 0;
  stats.packets = 0;

  int socket_fd = do_open_socket(options);
  for (; options->packets != 0; options->packets--) {
    int icmp_hdr_len = sizeof(struct icmphdr);
    struct icmphdr *icmp_hdr_ptr = do_malloc(icmp_hdr_len);
    if (icmp_hdr_ptr == NULL) {
      return -1;
    }
    char *icmp_packet_ptr = do_malloc(sizeof(char) * options->icmp_len);
    if (icmp_packet_ptr == NULL) {
      return -1;
    }

    clock_gettime(CLOCK_REALTIME, &tstart);
    int rc = do_send_icmp(socket_fd, options, icmp_packet_ptr);
    clock_gettime(CLOCK_REALTIME, &tend);
    if (rc == 0) {
      printf("error: icmp connection was reset. errno:%d\n", errno);
    } else if (rc == -1) {
      // EAGAIN indicate that select(3) hit timeout and recvfrom(3) don't have data to read
      if (errno == EAGAIN) {
        printf("error: icmp connection timeout. errno:%d\n", errno);
      } else {
        printf("error: icmp connection was interrupted. errno:%d\n", errno);
      }
    } else if (rc < (int)sizeof(icmp_hdr_len)) {
      printf("error: received icmp packet shorter than icmp header\n");
    } else {
      // rtt - round trip time is a time in ms which took for packet to travel (forth and back)
      rtt = do_timespec_delta(tstart, tend);
      memset(&ttl, 0, sizeof(ttl));
      // FIXME: rewrite ugly hack with 9th byte offset - get ttl from ip header (ttl is 9th byte)
      memcpy(&ttl, icmp_packet_ptr + 8, sizeof(ttl));
      // reuse of icmp_hdr_ptr to fetch returned sequence
      memset(icmp_hdr_ptr, 0, icmp_hdr_len);
      // since SOCK_RAW is used - icmp_packet_ptr will hold 20 bytes of ipv4 header (which we need to strip off)
      memcpy(icmp_hdr_ptr, icmp_packet_ptr + 20, icmp_hdr_len);
      if (icmp_hdr_ptr->type == ICMP_ECHOREPLY) {
        printf("seq=%d; time=%.1fms; ttl=%d\n", ntohs(icmp_hdr_ptr->un.echo.sequence), rtt, ttl);
      } else {
        printf("error: received wrong icmp packet type:%d\n", icmp_hdr_ptr->type);
      }
    }
    do_free(icmp_hdr_ptr);
    do_free(icmp_packet_ptr);
    
    // account statistic
    stats.packets++;
    stats.tot_ms += rtt;
    if (rtt > stats.max_ms) {
      stats.max_ms = rtt;
    }
    if (rtt < stats.min_ms) {
      stats.min_ms = rtt;
    }

    // FIXME: convert to nanosleep
    sleep(options->interval);
  }
  do_display_summary(&stats);
  close(socket_fd);
  return 0;
}


int main(int argc, char **argv)
{
  struct arguments arguments;
  arguments.icmp_type = ICMP_ECHO;
  arguments.icmp_len = 4096;
  arguments.icmp_sequence = 12;
  // FIXME: rename icmp_idi to something more intuitive
  arguments.icmp_idi = getpid();
  arguments.icmp_payload = "....";
  arguments.packets = 10;
  arguments.interval = 1;
  arguments.timeout = 1;
  arguments.ttl = 28;
  arguments.max_rtt = 100;
  arguments.min_rtt = 1;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  int rc = do_main_loop(&arguments);
  return rc;
}
