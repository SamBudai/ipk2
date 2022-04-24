#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <time.h>

#define MAX 101
#define SIZE_ETHERNET 14
char error_buffer[PCAP_ERRBUF_SIZE];

/** From
 * Programing with pcap
 * https://www.tcpdump.org/pcap.html
 */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/**
 * Print all existing interfaces on current machine
 *
 * From:
 * C - pcap_findalldevs to display all interfaces is stuck in an infinite loop
 * https://stackoverflow.com/questions/61370713/c-pcap-findalldevs-to-display-all-interfaces-is-stuck-in-an-infinite-loop
 *
 */
void print_all_interfaces() {
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, error_buffer) == 0) {
        for (pcap_if_t  *interface = interfaces; interface != NULL; interface = interface->next) {
            printf("%s\n", interface->name);
        }
        pcap_freealldevs(interfaces);
    }
    else
        fprintf(stderr,"Error in pcap_findall_devs(): %s\n", error_buffer);
}

/**
 * Same principle as printing all interfaces, but checking if name is valid interface
 */
void check_interface(char *name) {
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, error_buffer) == 0) {
        for (pcap_if_t *interface = interfaces; interface != NULL; interface = interface->next) {
            if(strcmp(interface->name, name) == 0){
                pcap_freealldevs(interfaces);
                return;
            }
        }
        pcap_freealldevs(interfaces);
        fprintf(stderr,"Error: Interface %s does not exists\n", name);
        exit(1);
    }
}

/**
 * Creating expression for pcap_filter
 */
void create_filter_expression(char str[], int port, int tcp_flag, int udp_flag, int arp_flag, int icmp_flag){
    if(port != -1){ // if port was given, add port to filter
        char port_number[20];
        sprintf(port_number, "%d", port);

        // adding port to expression
        strcpy(str, "port ");
        strcat(str,  port_number);
        strcat(str, " and (");
    }

    bool first = true;

    if(tcp_flag || port != -1){ // add tcp to filter if tcp_flag is 1 or port was not given
        if(first){
            strcat(str, "tcp");
            first = false;
        }
        else{
            strcat(str, " or ");
            strcat(str, "tcp");
        }
    }

    if(udp_flag || port != -1){ // add udp to filter if udp_flag is 1 or port was not given
        if(first){
            strcat(str, "udp");
            first = false;
        }
        else{
            strcat(str, " or ");
            strcat(str, "udp");
        }
    }

    if(arp_flag){
        if(first){
            strcat(str, "arp");
            first = false;
        }
        else{
            strcat(str, " or ");
            strcat(str, "arp");
        }
    }

    if(icmp_flag){
        if(first){
            strcat(str, "icmp or icmp6");
            first = false;
        }
        else{
            strcat(str, " or ");
            strcat(str, "icmp or icmp6");
        }
    }

    if(port != -1) // if port was given, end expression with ')'
        strcat(str, ")");
}

/**
 * Convert timeval to printable string
 *
 * From:
 * I'm trying to build an RFC3339 timestamp in C. How do I get the timezone offset?
 * https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
 * https://zetcode.com/articles/cdatetime/
 **/
void timeval_to_string(struct timeval time, char result[]){
    static char buffer[128], time_buffer[64];
    time_t time_in_sec = time.tv_sec;
    struct tm *tm = localtime(&time_in_sec);

    strftime(time_buffer, sizeof time_buffer, "%FT%T", tm);
    snprintf(buffer, sizeof buffer, "%s.%03ld", time_buffer, time.tv_usec/1000);
    strncpy(result, buffer, 128);
    strftime(time_buffer, 64, "%z", tm);
    strncat(result, time_buffer, 64);
}

/**
 * Get mac address in right format from string
 *
 * From:
 * Is these a way to set the output of printf to a string?
 * https://stackoverflow.com/questions/19382198/is-these-a-way-to-set-the-output-of-printf-to-a-string
 */
void get_mac_address(char *mac_buffer, const u_char *mac_bytes) {
    snprintf(mac_buffer, INET6_ADDRSTRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
}

/**
 * Hexdump function for writing out packet informations
 *
 * From:
 * Let's Build a Hexdump Utility in C
 * http://www.dmulholl.com/lets-build/a-hexdump-utility.html
 */
void print_packet_data(const u_char *data, bpf_u_int32 length){
    int line_counter = 0x0000;
    for(bpf_u_int32 i = 0; i < length; i+= 0x10) {
        printf("0x%04x: ", line_counter);
        line_counter += 0x0010;

        for (bpf_u_int32 j = 0; j < 0x10; j++) {
            if (j > 0 && j % 4 == 0)
                printf(" ");
            if (i+j < length)
                printf(" %02x", data[i+j]);
            else
                printf("   ");
        }

        printf("  ");

        for (bpf_u_int32 j = 0; j < 0x10 && i+j < length; j++) {
            if (isprint(data[i+j]))
                printf("%c", data[i+j]);
            else
                printf(".");
        }
        printf("\n");
    }
    printf("\n");
}

/**
 *  Callback function for caught packets for pcap_loopback
 *  Process packet and write all information in right format to stdin
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet){

    char mac[INET6_ADDRSTRLEN];
    char time_buf[256];
    const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(packet);

    // Printf all information which are the same for every used protocol
    timeval_to_string(header->ts, time_buf);
    printf("timestamp: %s\n", time_buf);

    get_mac_address(mac, ethernet->ether_shost);
    printf("src MAC: %s\n", mac);

    get_mac_address(mac, ethernet->ether_dhost);
    printf("dst MAC: %s\n", mac);

    printf("frame length: %d bytes\n", header->len);

    // IPv4
    if (ntohs(ethernet->ether_type) == ETHERTYPE_IP) {
        u_char *ip_protocol = (u_char *)(packet + SIZE_ETHERNET + 9); // src_protocol offset

        struct in_addr *ip_src = (struct in_addr *)(packet + SIZE_ETHERNET + 12); // src_ip offset
        struct in_addr *ip_dst = (struct in_addr *)(packet + SIZE_ETHERNET + 16); // dst_ip offset

        u_char *ip_vhl = (u_char *)(packet + SIZE_ETHERNET);
        u_int size_ip = (*ip_vhl & 0x0f) * 4;

        printf("src IP: %s\n", inet_ntoa(*ip_src));
        printf("dst IP: %s\n", inet_ntoa(*ip_dst));

        if(*ip_protocol == IPPROTO_TCP || *ip_protocol == IPPROTO_UDP) {
            u_short *src_protocol = (u_short *)(packet + SIZE_ETHERNET + size_ip); // offset for tcp/udp
            u_short *dst_protocol = (u_short *)(packet + SIZE_ETHERNET + size_ip + sizeof(u_short));

            printf("src port: %u\n", ntohs(*src_protocol));
            printf("dst port: %u\n", ntohs(*dst_protocol));
        }
    }
    // IPv6
    else if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV6) {

        char ipv6[INET6_ADDRSTRLEN] = "";
        struct in6_addr *src_ip = (struct in6_addr *)(packet + SIZE_ETHERNET + 8);
        struct in6_addr *dst_ip = (struct in6_addr *)(packet + SIZE_ETHERNET + 24);

        u_char *protocol = (u_char *)(packet + SIZE_ETHERNET + 6);

        inet_ntop(AF_INET6, src_ip, ipv6, INET6_ADDRSTRLEN);
        printf("src IP: %s\n", ipv6);

        inet_ntop(AF_INET6, dst_ip, ipv6, INET6_ADDRSTRLEN);
        printf("dst IP: %s\n", ipv6);

        if(*protocol == IPPROTO_TCP || *protocol == IPPROTO_UDP) {

            u_short *src_protocol = (u_short *)(packet + SIZE_ETHERNET + 40); // offset for tcp/udp, ipv6 has fixed length
            u_short *dst_protocol = (u_short *)(packet + SIZE_ETHERNET + 40 + sizeof(u_short));

            printf("src port: %u\n", ntohs(*src_protocol));
            printf("dst port: %u\n", ntohs(*dst_protocol));
        }
    }
    print_packet_data(packet, header->len);
}

int main(int argc, char *argv[]) {

    char interface[MAX] = "";
    int port = -1;
    int tcp_flag = 0;
    int udp_flag = 0;
    static int icmp_flag = 0;
    static int arp_flag = 0;
    int count = 0;

    pcap_t *handle;

    struct bpf_program filter;
    char filter_expression[255] = "";

    // From:
    // Parsing program options using getopt
    // https://www.gnu.org/software/libc/manual/html_node/Getopt.html
    static struct option long_options[] =
            {
                    {"interface", optional_argument, 0, 'i'},
                    {"tcp", no_argument, 0, 't'},
                    {"udp", no_argument, 0, 'u'},
                    {"arp", no_argument, &arp_flag, 1},
                    {"icmp", no_argument, &icmp_flag, 1},
            };

    int option_index = 0;
    int option;

    // From:
    // Parsing program options using getopt
    // https://www.gnu.org/software/libc/manual/html_node/Getopt.html
    while((option = getopt_long (argc, argv, "i::p:tun:", long_options, &option_index)) != -1) {
        switch (option) {
            case 0:
                break;
            case 'i':
                if(argv[optind] == NULL)
                    break;
                if(argv[optind][0] == '-'){
                    print_all_interfaces();
                    exit(0);
                }
                strncpy(interface, argv[optind], MAX - 1);
                break;
            case 'p':
                for(size_t i= 0; i<strlen(optarg); i++)
                    if(!isdigit(optarg[i])){
                        fprintf(stderr,"Error: value for option -p is not a valid number\n");
                        exit(1);
                    }
                port = atoi(optarg);
                break;
            case 't':
                tcp_flag = 1;
                break;
            case 'u':
                udp_flag = 1;
                break;
            case 'n':
                for(size_t i= 0; i<strlen(optarg); i++) {
                    if (!isdigit(optarg[i])) {
                        fprintf(stderr, "Error: value for option -n is not a valid number\n");
                        exit(1);
                    }
                }
                count = atoi(optarg);
                break;
            case '?':
                fprintf(stderr,"Unknown option during argument parsing\n");
                exit(1);
            default:
                fprintf(stderr,"Error occurred while parsing args: getopt returned %d\n", option);
                exit(1);
        }
    }

    if(strlen(interface) < 1){ // if interface was not set, print all interfaces
        print_all_interfaces();
        exit(0);
    }

    check_interface(interface); // Check if given interface is valid

    if((tcp_flag || udp_flag || arp_flag || icmp_flag) != 1) // if no protocol was set, catch all protocols
        tcp_flag = udp_flag = arp_flag = icmp_flag = 1;

    if(count < 1) // if -n was not set, catch one packet
        count = 1;

    // From:
    // Using libpcap in C
    // https://www.devdungeon.com/content/using-libpcap-c
    handle = pcap_open_live(interface, BUFSIZ, 1, 1500, error_buffer);
    if(handle == NULL){
        fprintf(stderr,"Error: can not open specified device %s\n", interface);
        exit(2);
    }

    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", interface);
        return(2);
    }

    // From:
    // Ubuntu Manpage: pcap-filter
    // https://manpages.ubuntu.com/manpages/focal/man7/pcap-filter.7.html
    create_filter_expression(filter_expression, port, tcp_flag, udp_flag, arp_flag, icmp_flag);

    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    if (pcap_compile(handle, &filter, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expression, pcap_geterr(handle));
        return(2);
    }

    // From:
    // Programing with pcap
    // https://www.tcpdump.org/pcap.html
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expression, pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, count, got_packet, NULL);
    pcap_freecode(&filter);
    pcap_close(handle);
    return 0;
}