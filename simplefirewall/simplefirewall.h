#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_FW_POLICY	5

typedef enum policyType {INPUT, OUTPUT} policyType;
typedef enum protocolType {TCP, UDP, OTHER} protocolType;

const unsigned char any[4] = {0,0,0,0};

typedef struct simplefirewall_policy{
  policyType policyType;
  protocolType protocolType;
  
  unsigned char srcIp[4];
  int srcPort;
  unsigned char destIp[4] ; 
  int destPort;
  
  
} simplefirewall_policy;

//static policy support 5 rules
static simplefirewall_policy simplefirewall_polices[5];

//NF_IP_PRE_ROUTING for inbound
static struct nf_hook_ops simpleFirewall_netfilter_ops_in; 
//NF_IP_POST_ROUTING for outbound
static struct nf_hook_ops simpleFirewall_netfilter_ops_out;


