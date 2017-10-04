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
  gcc main.c -o ping; sudo chown root:root ping; sudo chmod ugo+rxs ping

  - server uptime by tsval
  - account information for statistic
  - visual display of packets
  - display info by icmp->code (https://gist.github.com/kbaribeau/4495181)

  FIXME: 
    - timeout issue (actually timeout doesn't work as expected)
    - max rtt sometime have too high value
    - add default arguments
    - break down ICMP responses, so not everything will be covered by 'wrong packet'
  TODO:
    - convert errno from numeric to word values
    - show ICMP_TYPE as word and numeric values
    - bring (kore) a webserver and when client connects render a webgraph in live?
    - DNS to IP; check IP
*/

#define ARGS_DEFAULT_PACKETS 10
#define ARGS_DEFAULT_TIMEOUT 1
#define ARGS_DEFAULT_INTERVAL 1
#define ARGS_DEFAULT_TTL 32

const char *argp_program_version = "0.0.5";
const char *argp_program_bug_address = "<dev@null>";
static char args_doc[] = "DESTINATION";
static struct argp_option options[] = {
  {"count",    'c', "NUM",  0, "packets to send (default: 10)", 0},
  {"interval", 'i', "SECS", 0, "time to wait between packets (default: 1)", 0},
  {"timeout",  't', "SECS", 0, "time to wait for socket to be ready (select) (default: 1)", 0},
  {"ttl",      'T', "NUM",  0, "packet ttl (default: 32)", 0},
  {0}
};

char *IP;
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
    case 'i':
      arguments->interval = atoi(arg);
      break;
    case 't':
      arguments->timeout = atoi(arg);
      break;
    case 'T':
      arguments->ttl = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      arguments->ip = arg;
      break;
    case ARGP_KEY_NO_ARGS:
      argp_usage(state);
      break;
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

const char *icmp_type_to_string(int type)
{
  /*
   * convert appropriate icmphdr->type to a string
   * @type  - icmphdr->type
   * return - string representation of icmphdr->type
   *
   */
  switch(type) {
    case ICMP_ECHOREPLY:
      return "echoreply";
    case ICMP_DEST_UNREACH:
      return "dest_unreach";
    case ICMP_SOURCE_QUENCH:
      return "source_quench";
    case ICMP_REDIRECT:
      return "redirect";
    case ICMP_ECHO:
      return "echo";
    case ICMP_TIME_EXCEEDED:
      return "time_exceeded";
    case ICMP_PARAMETERPROB:
      return "parameterprob";
    case ICMP_TIMESTAMP: 
      return "timestamp";
    case ICMP_TIMESTAMPREPLY:
      return "timestampreply";
    case ICMP_INFO_REQUEST:
      return "info_request";
    case ICMP_INFO_REPLY:
      return "info_reply";
    case ICMP_ADDRESS:
      return "address";
    case ICMP_ADDRESSREPLY:
      return "addressreply";
  }
  return "null";
}

const char *icmp_code_to_string(int type, int code)
{
  /*
   * convert appropriate icmphdr->code to a string;
   * @type  - icmphdr->type
   * @code  - icmphdr->code
   * return - string representation of icmp code
   *
   */
  switch(type) {
    case ICMP_DEST_UNREACH:
      switch(code) {
        case ICMP_NET_UNREACH:
          return "net_unreach";
        case ICMP_HOST_UNREACH:
          return "host_unreach";
        case ICMP_PROT_UNREACH:
          return "prot_unreach";
        case ICMP_PORT_UNREACH:
          return "port_unreach";
        case ICMP_FRAG_NEEDED:
          return "frag_needed";
        case ICMP_SR_FAILED:
          return "sr_failed:";
        case ICMP_NET_UNKNOWN:
          return "net_unknown";
        case ICMP_HOST_UNKNOWN:
          return "host_unknown:";
        case ICMP_HOST_ISOLATED:
          return "host_isolated";
        case ICMP_NET_ANO:
          return "net_ano";
        case ICMP_HOST_ANO:
          return "host_ano";
        case ICMP_NET_UNR_TOS:
          return "net_unr_tos:";
        case ICMP_HOST_UNR_TOS:
          return "host_unr_tos";
        case ICMP_PKT_FILTERED:
          return "pkt_filtered";
        case ICMP_PREC_VIOLATION:
          return "prec_violation";
        case ICMP_PREC_CUTOFF:
          return "prec_cutoff";
      }
      break;
    case ICMP_REDIRECT:
      switch(code) {
        case ICMP_REDIR_NET:
          return "redir_net";
        case ICMP_REDIR_HOST:
          return "redir_host";
        case ICMP_REDIR_NETTOS:
          return "redir_nettos";
        case ICMP_REDIR_HOSTTOS:
          return "redir_hosttos";
      }
      break;
    case ICMP_TIME_EXCEEDED:
      switch(code) {
        case ICMP_EXC_TTL:
          return "exc_ttl";
        case ICMP_EXC_FRAGTIME:
          return "exc_fragtime";
      }
      break;
  }
  return "null";

}

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
  printf("min rtt=%.2fms; max rtt=%.2fms; avg rtt=%.2fms\n", s->min_ms, s->max_ms, (s->tot_ms/s->packets));
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
  //FIXME: pass back ip to caller
  struct sockaddr_in from;
  socklen_t len = sizeof(from);
  // read response from socket and write to packet_ptr buffer
  memset(packet_ptr, 0, options->icmp_len);
  //rc = recvfrom(socket_fd, packet_ptr, options->icmp_len, MSG_DONTWAIT, NULL, NULL);
  rc = recvfrom(socket_fd, packet_ptr, options->icmp_len, MSG_DONTWAIT, (struct sockaddr*)&from, &len);
  IP = inet_ntoa(from.sin_addr);
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
  //FIXME: bug with ttl. on some nodes it give high value (e.g. node 123.123.23.23)
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

      const char *icmp_type = icmp_type_to_string(icmp_hdr_ptr->type);
      const char *icmp_code = icmp_code_to_string(icmp_hdr_ptr->type, icmp_hdr_ptr->code);
      short int icmp_sequ = ntohs(icmp_hdr_ptr->un.echo.sequence);
      printf("src=%s rtt=%.2fms ttl=%d seq=%d type=%s code=%s\n", IP, rtt, ttl, icmp_sequ, icmp_type, icmp_code);
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

    // don't sleep on last packet ;-)
    if (options->packets > 1) {
      // FIXME: convert to nanosleep
      sleep(options->interval);
    }
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
  arguments.packets = ARGS_DEFAULT_PACKETS;
  arguments.interval = ARGS_DEFAULT_INTERVAL;
  arguments.timeout = ARGS_DEFAULT_TIMEOUT;
  arguments.ttl = ARGS_DEFAULT_TTL;
  arguments.max_rtt = 100;
  arguments.min_rtt = 1;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  int rc = do_main_loop(&arguments);
  return rc;
}
