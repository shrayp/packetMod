#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/random.h>

/* Netfilter */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* Socket Buffer Structure and TCP Protocals */
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/in.h>

/* ip header parts */
__u8                        type_of_service, 
                            time_to_live, 
                            protocol;
__u16                       total_len, 
                            id, 
                            fragment_offset;
__u32                       source_addr, 
                            dest_addr;

static struct nf_hook_ops   nfho;               //Netfilter hook

/******************************************************************************/

/* converts and prints a long int representation of an IP address to a dotted decimal representation */
void print_ip(int ip)
{ 
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printk("IP: %d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void print_payload(unsigned char *head, unsigned char *tail)
{
    unsigned char *iter; //TCP data iterator

    printk("data:\n");
    for (iter = head; iter != tail; ++iter) {
        char c = *(char *)iter;
        if (c == '\0'){ break; }
        printk("%c", c);
    }
    printk("\n\n");
}

void break_payload(unsigned char *head, unsigned char *tail)
{
    unsigned char *iter;
    int randint;

    for (iter = head; iter != tail; ++iter) {
        char c = *(char *)iter;
        if (c == '\0'){ break; }
        
        randint = get_random_int();

        if(randint % 2 == 0){
            *iter = *iter << 2;    
        } else {
            *iter = *iter >> 2;
        }
        
    }
}

/******************************************************************************/
/* Hook to catch all packets, incoming and outgoing */
unsigned int accept_all_hook(unsigned int hooknum, 
                        struct sk_buff *skb,            //Socket Buffer
                        const struct net_device *in,    //Input device
                        const struct net_device *out,   //output device
                        int (*okfn)(struct sk_buff *))  //output buffer??
{
    struct tcphdr *tcp_header;                          //TCP header
    struct iphdr  *ip_header;                           //IP Header
    struct sk_buff *socket_buffer;                      //socket buffer
    __u32 src_addr, dest_addr;                          //Source and destination addresses
    __u16 src_port, dest_port;                          //Source and destination ports
    unsigned char *data_head;                           //TCP data head pointer
    unsigned char *data_tail;                           //TCP data tail pointer
    int randint = get_random_int();                     //random variable to print or break payload


    socket_buffer = skb_copy(skb,GFP_ATOMIC);           //copy socket buffer into memory

    if (!socket_buffer) { return NF_ACCEPT; }           //if empty packet is recieved
        
    
    ip_header = (struct iphdr*)skb_network_header(socket_buffer);

    if (ip_header->protocol != IPPROTO_TCP){            //ignore all non TCP packets
        return NF_ACCEPT;
    }

    tcp_header = tcp_hdr(skb);                          //Grab TCP Header

    src_addr    = ntohl(ip_header->saddr);              //Convert headers and ports from network format to host format
    dest_addr   = ntohl(ip_header->daddr);
    src_port    = ntohs(tcp_header->source);
    dest_port   = ntohs(tcp_header->dest);

    data_head = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
    data_tail = skb_tail_pointer(skb);

    printk("Source Address: ");
    print_ip(src_addr);
    printk("Destination Address: ");
    print_ip(dest_addr);

    if ((randint % 2) == 0){
        print_payload(data_head,data_tail);
    } else {
        break_payload(data_head,data_tail);
    }
    

    return NF_ACCEPT;
}

/******************************************************************************/
/* Init Module function */
static int __init mod_init(void)
{
    nfho.hook = (nf_hookfn*)accept_all_hook;        //Define hook to be used as custon hook written above
    nfho.hooknum = 0;                               //NF_IP_PRE_ROUTING defined as '0' in netfilter_ipv4.h line 45 which defines a
                                                    //hook to be called as soon as packet is recieved for filtering
    nfho.pf = PF_INET;                              //Packet Family for this hook is IPV4
    nfho.priority = NF_IP_PRI_FIRST;                //set to highest priority over all other hook functions
    nf_register_hook(&nfho);                        //regester hook in netfilter
    printk ("myModule: netfilter hook regestered\n");
    
    return 0;
}

/* module exit function */ 
static void __exit mod_cleanup(void)
{
    printk ("myModule: unregister hook\n");
    nf_unregister_hook(&nfho);              //cleanup hook
}

module_init(mod_init);
module_exit(mod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shrayansh Pandey");
MODULE_DESCRIPTION("Simple Packet Module");