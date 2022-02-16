#include "simplefirewall.h"
/*
• Prevent A from doing telnet to Machine B.
• Prevent B from doing telnet to Machine A.
• Prevent A from visiting an external web site NYIT.edu (64.35.176.173).
*/


void init_policies(void) {
	//for rule 1, Prevent A from doing telnet to Machine B.
	simplefirewall_polices[0].policyType = OUTPUT;
	simplefirewall_polices[0].protocolType = TCP;
	//ANY
	simplefirewall_polices[0].srcIp[0] = 0;
	simplefirewall_polices[0].srcIp[1] = 0;
	simplefirewall_polices[0].srcIp[2] = 0;
	simplefirewall_polices[0].srcIp[3] = 0;
	simplefirewall_polices[0].srcPort = -1; //ANY
	//destination address of Machine B
	simplefirewall_polices[0].destIp[0] = 172; 
	simplefirewall_polices[0].destIp[1] = 16; 
	simplefirewall_polices[0].destIp[2] = 0; 
	simplefirewall_polices[0].destIp[3] = 4; 
	simplefirewall_polices[0].destPort = 23;
	
	//for rules 2, Prevent B from doing telnet to Machine A.
	simplefirewall_polices[1].policyType = INPUT;
	simplefirewall_polices[1].protocolType = TCP;
	//ANY
	simplefirewall_polices[1].srcIp[0] = 172;
	simplefirewall_polices[1].srcIp[1] = 16;
	simplefirewall_polices[1].srcIp[2] = 0;
	simplefirewall_polices[1].srcIp[3] = 4;
	simplefirewall_polices[1].srcPort = -1; //ANY
	//destination address of Machine A
	simplefirewall_polices[1].destIp[0] = 172; 
	simplefirewall_polices[1].destIp[1] = 16; 
	simplefirewall_polices[1].destIp[2] = 0; 
	simplefirewall_polices[1].destIp[3] = 5;
	simplefirewall_polices[1].destPort = 23;
	
	//for rule 3, Prevent A from visiting an external web site NYIT.edu (64.35.176.173) via HTTP.
	simplefirewall_polices[2].policyType = OUTPUT;
	simplefirewall_polices[2].protocolType = TCP;
	//ANY
	simplefirewall_polices[2].srcIp[0] = 0;
	simplefirewall_polices[2].srcIp[1] = 0;
	simplefirewall_polices[2].srcIp[2] = 0;
	simplefirewall_polices[2].srcIp[3] = 0;
	simplefirewall_polices[2].srcPort = -1; //ANY
	//destination address of NYIT.edu (64.35.176.173).
	simplefirewall_polices[2].destIp[0] = 64; 
	simplefirewall_polices[2].destIp[1] = 35; 
	simplefirewall_polices[2].destIp[2] = 176; 
	simplefirewall_polices[2].destIp[3] = 173;
	simplefirewall_polices[2].destPort = 80; //for HTTP
	
	//for rule 4, Prevent A from visiting an external web site NYIT.edu (64.35.176.173) via HTTPS.
	simplefirewall_polices[3].policyType = OUTPUT;
	simplefirewall_polices[3].protocolType = TCP;
	//ANY
	simplefirewall_polices[3].srcIp[0] = 0;
	simplefirewall_polices[3].srcIp[1] = 0;
	simplefirewall_polices[3].srcIp[2] = 0;
	simplefirewall_polices[3].srcIp[3] = 0;
	simplefirewall_polices[3].srcPort = -1; //ANY
	//destination address of NYIT.edu (64.35.176.173).
	simplefirewall_polices[3].destIp[0] = 64; 
	simplefirewall_polices[3].destIp[1] = 35; 
	simplefirewall_polices[3].destIp[2] = 176; 
	simplefirewall_polices[3].destIp[3] = 173;
	simplefirewall_polices[3].destPort = 443; //for HTTPS
	
	//for rule 4, Prevent A send UDP to Machine B 
	simplefirewall_polices[4].policyType = OUTPUT;
	simplefirewall_polices[4].protocolType = UDP;
	//ANY                  
	simplefirewall_polices[4].srcIp[0] = 0;
	simplefirewall_polices[4].srcIp[1] = 0;
	simplefirewall_polices[4].srcIp[2] = 0;
	simplefirewall_polices[4].srcIp[3] = 0;
	simplefirewall_polices[4].srcPort = -1; //ANY
	//destination address of Machine B
	simplefirewall_polices[4].destIp[0] = 172; 
	simplefirewall_polices[4].destIp[1] = 16; 
	simplefirewall_polices[4].destIp[2] = 0; 
	simplefirewall_polices[4].destIp[3] = 4;
	simplefirewall_polices[4].destPort = -1; //ANY
}

bool matchIP(unsigned char ip1[4], unsigned char ip2[4], unsigned char any[4])
{
	if(any == NULL)
	{
		//this is not to handle any wildcard case
		if(	ip1[0] != ip2[0] ||
			ip1[1] != ip2[1] ||
			ip1[2] != ip2[2] ||
			ip1[3] != ip2[3] )
		{
			//dest ip not match, skip
			return false;
		}
		 
	}
	else
	{
		//this require to handle any wildcard case
		if(	(ip1[0]  != any[0] || 
			ip1[1]  != any[1] ||
			ip1[2]  != any[2] || 
			ip1[3]  != any[3]) && 
			(ip2[0]  != any[0] || 
			ip2[1]  != any[1] ||
			ip2[2]  != any[2] || 
			ip2[3]  != any[3])) 
		{		
			//this is not wildcard case, check src ip
			if(	ip1[0] != ip2[0] ||
				ip1[1] != ip2[1] ||
				ip1[2] != ip2[2] ||
				ip1[3] != ip2[3] )
			{
				//dest ip not match, skip
				return false;
			}
					
		}
		//this is wildcard case
	}
	
	return true;
}

unsigned int simpleFirewall_out_hook(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  simplefirewall_policy *current_policy;
  register int i;
  
  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;
  
  printk(KERN_DEBUG "simpleFirewall_out_hook: its packet from %d.%d.%d.%d to %d.%d.%d.%d\n",
			((unsigned char *)&iph->saddr)[0],
			((unsigned char *)&iph->saddr)[1],
			((unsigned char *)&iph->saddr)[2],
			((unsigned char *)&iph->saddr)[3],
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);

  for(i=0; i< MAX_FW_POLICY; i++)
  {
	  printk(KERN_DEBUG "simpleFirewall_out_hook: Walk though the policy %d.\n", i); 
	  current_policy = &simplefirewall_polices[i];
	  if((*current_policy).policyType != OUTPUT)
	  {
		  printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is inbound policy skip it.\n", i); 
		  continue;
	  }
	  printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is outbound policy start process the condition [%d]\n", i, (*iph).protocol); 
	  
	  switch((*iph).protocol)
	  {
		  case IPPROTO_TCP:
		    //this is tcp copnnection
			if((*current_policy).protocolType != TCP)
			{
				//this is not match protocol, skip it
				continue;
			}
			
			/*
			//check src ip
			if(	(*current_policy).srcIp[0]  != 0 || 
				(*current_policy).srcIp[1]  != 0 ||
				(*current_policy).srcIp[2]  != 0 || 
				(*current_policy).srcIp[3]  != 0) 
			{		
				//this is not wildcard case, check src ip
				if(	((unsigned char *)&iph->saddr)[0] != (*current_policy).srcIp[0] ||
					((unsigned char *)&iph->saddr)[1] != (*current_policy).srcIp[1] ||
					((unsigned char *)&iph->saddr)[2] != (*current_policy).srcIp[2] ||
					((unsigned char *)&iph->saddr)[3] != (*current_policy).srcIp[3] )
				{
					//src ip not match, skip
					continue;
				}
				printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match src ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->saddr)[0],
					((unsigned char *)&iph->saddr)[1],
					((unsigned char *)&iph->saddr)[2],
					((unsigned char *)&iph->saddr)[3]); 
	  		
			}
			
			//check dest ip
			if(	(*current_policy).destIp[0]  != 0 || 
				(*current_policy).destIp[1]  != 0 ||
				(*current_policy).destIp[2]  != 0 || 
				(*current_policy).destIp[3]  != 0) 
			{		
				//this is not wildcard case, check src ip
				if(	((unsigned char *)&iph->daddr)[0] != (*current_policy).destIp[0] ||
					((unsigned char *)&iph->daddr)[1] != (*current_policy).destIp[1] ||
					((unsigned char *)&iph->daddr)[2] != (*current_policy).destIp[2] ||
					((unsigned char *)&iph->daddr)[3] != (*current_policy).destIp[3] )
				{
					//dest ip not match, skip
					continue;
				}
				
				printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match dest ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->daddr)[0],
					((unsigned char *)&iph->daddr)[1],
					((unsigned char *)&iph->daddr)[2],
					((unsigned char *)&iph->daddr)[3]); 
						
			}
			*/
			
			//check src ip
			if(matchIP(((unsigned char *)&iph->saddr),(*current_policy).srcIp,any)==false)
			{
				//src ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match src ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->saddr)[0],
					((unsigned char *)&iph->saddr)[1],
					((unsigned char *)&iph->saddr)[2],
					((unsigned char *)&iph->saddr)[3]); 
			
			//check dest ip
			if(matchIP(((unsigned char *)&iph->daddr),(*current_policy).destIp,any)==false)
			{
				//dest ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match dest ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->daddr)[0],
					((unsigned char *)&iph->daddr)[1],
					((unsigned char *)&iph->daddr)[2],
					((unsigned char *)&iph->daddr)[3]);
			
			//check src PORT
			if((*current_policy).srcPort != -1 && tcph->source != htons((*current_policy).srcPort))
			{
				//source port not match and not ANY, skip
				continue;
			}
			
			//check dest PORT
			if((*current_policy).destPort != -1 && tcph->dest != htons((*current_policy).destPort))
			{
				//dest port not match and not ANY, skip
				continue;
			}
			
			printk(KERN_INFO "simpleFirewall_out_hook: its packet to %d.%d.%d.%d\n",
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);
			
			printk(KERN_INFO "simpleFirewall_out_hook: this policy[%d] hit, DROP the packet",i);
			
			return NF_DROP;
			
			
			
		  break;
		  case IPPROTO_UDP:
			//this is UDP copnnection
			if((*current_policy).protocolType != UDP)
			{
				//this is not match protocol, skip it
				continue;
			}
			
			//check src ip
			if(matchIP(((unsigned char *)&iph->saddr),(*current_policy).srcIp,any)==false)
			{
				//src ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match src ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->saddr)[0],
					((unsigned char *)&iph->saddr)[1],
					((unsigned char *)&iph->saddr)[2],
					((unsigned char *)&iph->saddr)[3]); 
			
			//check dest ip
			if(matchIP(((unsigned char *)&iph->daddr),(*current_policy).destIp,any)==false)
			{
				//dest ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match dest ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->daddr)[0],
					((unsigned char *)&iph->daddr)[1],
					((unsigned char *)&iph->daddr)[2],
					((unsigned char *)&iph->daddr)[3]);
			
			//check src PORT
			if((*current_policy).srcPort != -1 && tcph->source != htons((*current_policy).srcPort))
			{
				//source port not match and not ANY, skip
				continue;
			}
			
			//check dest PORT
			if((*current_policy).destPort != -1 && tcph->dest != htons((*current_policy).destPort))
			{
				//dest port not match and not ANY, skip
				continue;
			}
			
			printk(KERN_INFO "simpleFirewall_out_hook: its packet to %d.%d.%d.%d\n",
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);
			
			printk(KERN_INFO "simpleFirewall_out_hook: this policy[%d] hit, DROP the packet",i);
			
			return NF_DROP;
		  break;
		  default:
			//other connection
			//this is UDP copnnection
			if((*current_policy).protocolType != OTHER)
			{
				//this is not match protocol, skip it
				continue;
			}
			
			
			
		  break;
	  }
	  
  }
  
  
  return NF_ACCEPT;
  
}

unsigned int simpleFirewall_in_hook(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;
  simplefirewall_policy *current_policy;
  register int i;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;
  printk(KERN_DEBUG "simpleFirewall_in_hook: its packet from %d.%d.%d.%d to %d.%d.%d.%d\n",
			((unsigned char *)&iph->saddr)[0],
			((unsigned char *)&iph->saddr)[1],
			((unsigned char *)&iph->saddr)[2],
			((unsigned char *)&iph->saddr)[3],
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);
  
  for(i=0; i< MAX_FW_POLICY; i++)
  {
	  printk(KERN_DEBUG "simpleFirewall_in_hook: Walk though the policy %d.\n", i); 
	  current_policy = &simplefirewall_polices[i];
	  if((*current_policy).policyType != INPUT)
	  {
		  printk(KERN_DEBUG "simpleFirewall_in_hook: this policy[%d] is outbound policy skip it.\n", i); 
		  continue;
	  }
	  printk(KERN_DEBUG "simpleFirewall_in_hook: this policy[%d] is inbound policy start process the condition[%d]\n", i, (*iph).protocol); 
	  
	  switch((*iph).protocol)
	  {
		  case IPPROTO_TCP:
		  //this is tcp copnnection
			if((*current_policy).protocolType != TCP)
			{
				//this is not match protocol, skip it
				continue;
			}
			
			//check src ip
			if(matchIP(((unsigned char *)&iph->saddr),(*current_policy).srcIp,any)==false)
			{
				//src ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match src ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->saddr)[0],
					((unsigned char *)&iph->saddr)[1],
					((unsigned char *)&iph->saddr)[2],
					((unsigned char *)&iph->saddr)[3]); 
			
			//check dest ip
			if(matchIP(((unsigned char *)&iph->daddr),(*current_policy).destIp,any)==false)
			{
				//dest ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match dest ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->daddr)[0],
					((unsigned char *)&iph->daddr)[1],
					((unsigned char *)&iph->daddr)[2],
					((unsigned char *)&iph->daddr)[3]);
			
			//check src PORT
			if((*current_policy).srcPort != -1 && tcph->source != htons((*current_policy).srcPort))
			{
				//source port not match and not ANY, skip
				continue;
			}
			
			//check dest PORT
			if((*current_policy).destPort != -1 && tcph->dest != htons((*current_policy).destPort))
			{
				//dest port not match and not ANY, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_in_hook: its packet to %d.%d.%d.%d\n",
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);
			
			printk(KERN_DEBUG "simpleFirewall_in_hook: this policy[%d] hit, DROP the packet",i);
			
			return NF_DROP;
			
			
			
		  break;
		  case IPPROTO_UDP:
		  //this is UDP copnnection
			if((*current_policy).protocolType != UDP)
			{
				//this is not match protocol, skip it
				continue;
			}
			
			//check src ip
			if(matchIP(((unsigned char *)&iph->saddr),(*current_policy).srcIp,any)==false)
			{
				//src ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match src ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->saddr)[0],
					((unsigned char *)&iph->saddr)[1],
					((unsigned char *)&iph->saddr)[2],
					((unsigned char *)&iph->saddr)[3]); 
			
			//check dest ip
			if(matchIP(((unsigned char *)&iph->daddr),(*current_policy).destIp,any)==false)
			{
				//dest ip not match, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_out_hook: this policy[%d] is match dest ip %d.%d.%d.%d or ANY (0.0.0.0)\n",i,
					((unsigned char *)&iph->daddr)[0],
					((unsigned char *)&iph->daddr)[1],
					((unsigned char *)&iph->daddr)[2],
					((unsigned char *)&iph->daddr)[3]);
			
			//check src PORT
			if((*current_policy).srcPort != -1 && tcph->source != htons((*current_policy).srcPort))
			{
				//source port not match and not ANY, skip
				continue;
			}
			
			//check dest PORT
			if((*current_policy).destPort != -1 && tcph->dest != htons((*current_policy).destPort))
			{
				//dest port not match and not ANY, skip
				continue;
			}
			
			printk(KERN_DEBUG "simpleFirewall_in_hook: this policy[%d] hit, DROP the packet",i);
			
			return NF_DROP;
		  break;
		  default:
		  //other connection
			
		  break;
	  }
	  
  }
  
  
  return NF_ACCEPT;
  
}

int setUpFilter(void) {
		printk(KERN_DEBUG "Simple Firewall is being setup.\n");
		printk(KERN_DEBUG "Simple Firewall init policies.\n");
		init_policies();
		
        printk(KERN_DEBUG "Registering a inbound filter.\n");
        simpleFirewall_netfilter_ops_in.hook = simpleFirewall_in_hook; 
        simpleFirewall_netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
        simpleFirewall_netfilter_ops_in.pf = PF_INET;
        simpleFirewall_netfilter_ops_in.priority = NF_IP_PRI_FIRST;

        // Register the inbound hook.
        nf_register_hook(&simpleFirewall_netfilter_ops_in);
		
		printk(KERN_DEBUG "Registering a outbound filter.\n");
        simpleFirewall_netfilter_ops_out.hook = simpleFirewall_out_hook; 
        simpleFirewall_netfilter_ops_out.hooknum = NF_INET_POST_ROUTING;
        simpleFirewall_netfilter_ops_out.pf = PF_INET;
        simpleFirewall_netfilter_ops_out.priority = NF_IP_PRI_FIRST;

        // Register the inbound hook.
        nf_register_hook(&simpleFirewall_netfilter_ops_out);
		

		
        return 0;
}

void removeFilter(void) {
        printk(KERN_DEBUG "Simple Firewall is being removed.\n");
        nf_unregister_hook(&simpleFirewall_netfilter_ops_in);
		nf_unregister_hook(&simpleFirewall_netfilter_ops_out);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");


