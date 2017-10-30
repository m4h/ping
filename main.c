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
#include <netdb.h>
#include <signal.h>

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
    - bug with negative sequence (ping -c -1 -i 0 127.0.0.1)
  TODO:
    - convert errno from numeric to word values
    - bring (kore) a webserver and when client connects render a webgraph in live?
    - add text graph display?
*/

// how it works - https://www.guyrutenberg.com/2008/12/20/expanding-macros-into-string-constants-in-c/
#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

#define ARGS_DEFAULT_PACKETS 15
#define ARGS_DEFAULT_TIMEOUT 5
#define ARGS_DEFAULT_INTERVAL 1
#define ARGS_DEFAULT_TTL 32
#define ARGS_DEFAULT_ICMP_ID getpid()
#define ARGS_DEFAULT_ICMP_TYPE ICMP_ECHO
#define ARGS_DEFAULT_ICMP_SEQUENCE 1
#define ARGS_DEFAULT_ICMP_LEN 64
#define ARGS_DEFAULT_ICMP_DATA "..."

const char *argp_program_version = "0.0.9";
const char *argp_program_bug_address = "https://github.com/m4h/ping/issues ._";
static char args_doc[] = "DESTINATION";
static struct argp_option options[] = {
  {"count",         'c', "NUM",  0, STR(packets to send (default: ARGS_DEFAULT_PACKETS)), 0},
  {"interval",      'i', "SECS", 0, STR(time to wait between packets (default: ARGS_DEFAULT_INTERVAL sec)), 0},
  {"timeout",       't', "SECS", 0, STR(time to wait for socket to be ready (select) (default: ARGS_DEFAULT_TIMEOUT sec)), 0},
  {"ttl",           'T', "NUM",  0, STR(packet ttl (default: ARGS_DEFAULT_TTL)), 0},
  {"icmp-type",     '1', "NUM",  0, STR(packet type (default: ARGS_DEFAULT_ICMP_TYPE)), 0},
  {"icmp-size",     '2', "NUM",  0, STR(packet size (default: ARGS_DEFAULT_ICMP_LEN)), 0},
  {"icmp-data",     '3', "STR",  0, STR(packet payload (default: ARGS_DEFAULT_ICMP_DATA)), 0},
  {"icmp-id",       '4', "NUM",  0, STR(sequence identifier (default: getpid())), 0},
  {"icmp-sequence", '5', "NUM",  0, STR(initial sequence number (default: ARGS_DEFAULT_ICMP_SEQUENCE)), 0},
  {0}
};

//FIXME: IP should be local
char *IP;

// account rtt, packets and other stuff
struct accounting ACCOUNTING;

// node is original (before DNS resolution) hostname/ip we are pinging
char *NODE;

struct arguments
{
  char          *node;          // hostname or ip address
  char          *ip;            // ip address
  uint16_t      icmp_type;
  uint32_t      icmp_len;
  char          *icmp_payload;
  uint32_t      icmp_echo_id;
  uint32_t      icmp_echo_seq;
  int           count;
  float         interval;
  int           timeout;
  // FIXME: min_ttl, max_ttl
  unsigned char ttl;
  double        max_rtt;
  double        min_rtt;
};

int hostname_to_ip(char *node, char *ip)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  struct sockaddr_in *addr;
  int rc;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  if ((rc = getaddrinfo(node, NULL, &hints, &result)) < 0) {
    printf("error: getaddrinfo: %s\n", gai_strerror(rc));
    return -1;
  }
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    addr = (struct sockaddr_in*)result->ai_addr;
    memcpy(ip, inet_ntoa(addr->sin_addr), 256);
    freeaddrinfo(result);
    break;
  }
  return 0;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct arguments *args = state->input;
  switch(key) {
    case 'c':
      args->count = atoi(arg);
      break;
    case 'i':
      args->interval = atoi(arg);
      break;
    case 't':
      args->timeout = atoi(arg);
      break;
    case 'T':
      args->ttl = atoi(arg);
      break;
    case '1':
      args->icmp_type = atoi(arg);
      break;
    case '2':
      args->icmp_len = atoi(arg);
      break;
    /* FIXME: complete copy
    case '3':
      args->icmp_payload = arg;
      break;
    */
    case '4':
      args->icmp_echo_id = atoi(arg);
      break;
    case '5':
      args->icmp_echo_seq = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      args->node = arg;
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

void do_display_summary(int signo)
{
  if (signo == SIGINT) {
    printf("--- ping %s statistics ---\n", NODE);
    printf("min rtt=%.2fms; max rtt=%.2fms; avg rtt=%.2fms\n", ACCOUNTING.min_ms, ACCOUNTING.max_ms, (ACCOUNTING.tot_ms/ACCOUNTING.packets));
    exit(0);
  }
}

int do_open_socket(struct arguments *arguments)
{
  int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_fd < 0) {
    printf("error: failed to open socket. errno: %d\n", errno);
    return -1;
  }
  // set TTL on IP packet 
  int rc = setsockopt(socket_fd, IPPROTO_IP, IP_TTL, &arguments->ttl, sizeof(arguments->ttl));
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

int do_send_icmp(int socket_fd, struct arguments *args, void *packet)
{
  // create ipv4 header
  struct sockaddr_in ip_hdr;
  struct in_addr ip_addr;
  inet_aton(args->ip, &ip_addr);
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
  //FIXME: add support for other icmp types
  switch(args->icmp_type) {
    case ICMP_ECHOREPLY:
      icmp_hdr_ptr->type = ICMP_ECHOREPLY;
      break;
    case ICMP_DEST_UNREACH:
      icmp_hdr_ptr->type = ICMP_DEST_UNREACH;
      break;
    case ICMP_ECHO:
      icmp_hdr_ptr->type = ICMP_ECHO;
      icmp_hdr_ptr->un.echo.sequence = htons(args->icmp_echo_seq++);
      break;
    case ICMP_TIMESTAMP:
      icmp_hdr_ptr->type = ICMP_TIMESTAMP;
      icmp_hdr_ptr->un.echo.sequence = htons(args->icmp_echo_seq++);
      break;
    case ICMP_ADDRESS:
      icmp_hdr_ptr->type = ICMP_ADDRESS;
      break;
    default:
      printf("error: invalid icmp type: %d\n", args->icmp_type);
      //FIXME: exit on incorrect icmp type
      return -1;
  }
  icmp_hdr_ptr->un.echo.id = htons(args->icmp_echo_id);
  icmp_hdr_ptr->checksum = 0;

  // create icmp packet (header + payload)
  // packet_ptr is used as icmp packet buffer (sent and recv)
  char *packet_ptr = do_malloc(args->icmp_len);
  if (packet_ptr == NULL) {
    return -1;
  }
  // copy icmp header to packet buffer
  memcpy(packet_ptr, icmp_hdr_ptr, icmp_hdr_len);
  // copy icmp payload to packet buffer
  memcpy(packet_ptr + icmp_hdr_len, args->icmp_payload, strlen(args->icmp_payload));
  int packet_len = icmp_hdr_len + strlen(args->icmp_payload);
  uint16_t checksum = icmp_checksum((uint16_t*)packet_ptr, packet_len);
  icmp_hdr_ptr->checksum = checksum;
  // copy icmp header with correct checksum
  memcpy(packet_ptr, icmp_hdr_ptr, icmp_hdr_len);
  
  // send packet over wire
  sendto(socket_fd, packet_ptr, packet_len, 0, (struct sockaddr*)&ip_hdr, sizeof(ip_hdr));
  // wait for response
  struct timeval timeout = {args->timeout, 0};
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
  memset(packet_ptr, 0, args->icmp_len);
  rc = recvfrom(socket_fd, packet_ptr, args->icmp_len, MSG_DONTWAIT, (struct sockaddr*)&from, &len);
  IP = inet_ntoa(from.sin_addr);
  memcpy(packet, packet_ptr, args->icmp_len);
  do_free(icmp_hdr_ptr);
  do_free(packet_ptr);
  return rc;
}

int do_main_loop(struct arguments *args)
{
  //FIXME: ./ping -c 123 -t -1 will ignore interval and ping without it
  //FIXME: ./ping -t 0  - lead to odd results
  double rtt;
  // variables used to compute and store rtt (round trip time) value
  struct timespec tstart, tend;
  // ttl (up to 256)
  unsigned char ttl;
  // accounting
  ACCOUNTING.max_ms = 65536;
  ACCOUNTING.min_ms = 0;
  ACCOUNTING.tot_ms = 0;
  ACCOUNTING.packets = 0;
  NODE = args->node;
  signal(SIGINT, do_display_summary);

  //FIXME: its buggy, incorrect and need to be rewrited (include hostname_to_ip), but it's works for now!
  // unbuffer stdout to display progress immediately
  setbuf(stdout, NULL);
  char ip[256];
  int rc = hostname_to_ip(args->node, ip);
  if (rc < 0) {
    return rc;
  }
  args->ip = ip;
  printf("--- ping %s (ttl=%d count=%d timeout=%d) ---\n", args->node, args->ttl, args->count, args->timeout);

  int socket_fd = do_open_socket(args);
  for (; args->count != 0; args->count--) {
    int icmp_hdr_len = sizeof(struct icmphdr);
    struct icmphdr *icmp_hdr_ptr = do_malloc(icmp_hdr_len);
    if (icmp_hdr_ptr == NULL) {
      return -1;
    }
    char *icmp_packet_ptr = do_malloc(sizeof(char) * args->icmp_len);
    if (icmp_packet_ptr == NULL) {
      return -1;
    }

    clock_gettime(CLOCK_REALTIME, &tstart);
    int rc = do_send_icmp(socket_fd, args, icmp_packet_ptr);
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
    ACCOUNTING.packets++;
    ACCOUNTING.tot_ms += rtt;
    if (rtt > ACCOUNTING.max_ms) {
      ACCOUNTING.max_ms = rtt;
    }
    if (rtt < ACCOUNTING.min_ms) {
      ACCOUNTING.min_ms = rtt;
    }

    // don't sleep on last packet ;-)
    if (args->count > 1) {
      // FIXME: convert to nanosleep
      sleep(args->interval);
    }
  }
  do_display_summary(SIGINT);
  close(socket_fd);
  return 0;
}

int main(int argc, char **argv)
{
  struct arguments args;
  args.icmp_echo_id = ARGS_DEFAULT_ICMP_ID;
  args.icmp_type = ARGS_DEFAULT_ICMP_TYPE;
  args.icmp_echo_seq = ARGS_DEFAULT_ICMP_SEQUENCE;
  args.icmp_len = ARGS_DEFAULT_ICMP_LEN;
  args.icmp_payload = ARGS_DEFAULT_ICMP_DATA;
  args.count = ARGS_DEFAULT_PACKETS;
  args.interval = ARGS_DEFAULT_INTERVAL;
  args.timeout = ARGS_DEFAULT_TIMEOUT;
  args.ttl = ARGS_DEFAULT_TTL;
  args.max_rtt = 100;
  args.min_rtt = 1;

  argp_parse(&argp, argc, argv, 0, 0, &args);
  int rc = do_main_loop(&args);
  return rc;
}
