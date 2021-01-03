#include <stdlib.h>
#include <syslog.h>
#include "populate.h"

struct options_rule
{
	char type1[10];
	char msg1[30];
	char type2[10];
	char msg2[30];

} typedef Options;

struct ids_rule
{
	char type_rule[10];
	char protocol[10];
	char address_source[IP_ADDR_LEN_STR];
	int port_source;
	char direction[3];
	char address_destination[IP_ADDR_LEN_STR];
	int port_destination;
	Options idso;
	int totalRules;
	
} typedef Rule;

void rule_matcher(Rule* rules_ds, ETHER_Frame* frame)
{
	for(int i = 0; i < rules_ds[0].totalRules; i++)
	{
		if(strcmp(rules_ds[i].address_source,"any") == 0||strcmp(rules_ds[i].address_source, frame->data.source_ip) == 0)
		{
			if(rules_ds[i].port_source == 0||rules_ds[i].port_source == frame->data.data.source_port)
			{
				if(strcmp(rules_ds[i].direction,"->") == 0)
				{
					if(strcmp(rules_ds[i].address_destination,"any") == 0||strcmp(rules_ds[i].address_destination,frame->data.destination_ip) == 0)
					{
						if(rules_ds[i].port_destination == 0||rules_ds[i].port_destination == frame->data.data.destination_port)
						{
							if(strcmp(rules_ds[i].protocol, frame->protocol) == 0)
							{
								if(strcmp(rules_ds[i].idso.type2, "NULL") == 0)
								{
									printf("Le paquet enfreint une regle\n");
						
									if(strcmp(rules_ds[i].type_rule, "alert") == 0)
									{
									openlog("IDS",LOG_PID|LOG_CONS,LOG_USER);
									syslog(LOG_INFO,rules_ds[i].idso.msg1);
									closelog();
									}
								}
								else if(strstr((char*)frame->data.data.data, rules_ds[i].idso.type2) != 0)
								{
								//if(strstr(frame->data.data.data, rules_ds[i].idso.type2) != 0)
														
									printf("Le paquet enfreint une regle\n");
									
									if(strcmp(rules_ds[i].type_rule, "alert") == 0)
									{
									openlog("IDS",LOG_PID|LOG_CONS,LOG_USER);
									syslog(LOG_INFO,rules_ds[i].idso.msg1);
									closelog();
									}
									
								}

								
							}
						}
					}
				}
			}
		}
	}
}

void read_rules(FILE* file, Rule* rules_ds, int count)
{
	//credits : cours
	char line[200];
	int ind = 0;
	while(fgets(line, 200, file) != NULL)
	{
		char tmp_line[strlen(line+1)];
		strcpy(tmp_line, line);
		char token[250];
		strcpy(token, strtok(tmp_line, " "));

		strcpy(rules_ds[ind].type_rule, token);

		strcpy(token, strtok(NULL, " "));
		strcpy(rules_ds[ind].protocol, token);

		strcpy(token, strtok(NULL, " "));
		strcpy(rules_ds[ind].address_source, token);

		strcpy(token, strtok(NULL, " "));
		rules_ds[ind].port_source = atoi(token);

		strcpy(token, strtok(NULL, " "));
		strcpy(rules_ds[ind].direction, token);

		strcpy(token, strtok(NULL, " "));
		strcpy(rules_ds[ind].address_destination, token);

		strcpy(token, strtok(NULL, " "));
		rules_ds[ind].port_destination = atoi(token);

		char* opt = strcpy(token, strtok(NULL, "("));

		strcpy(rules_ds[ind].idso.type1, strtok(opt, ":"));
		strcpy(opt, strtok(NULL, "\";"));
		strcpy(rules_ds[ind].idso.msg1, opt);
		
		strcpy(opt, strtok(NULL, ";"));
		
		//printf("%s\n", rules_ds[ind].idso.msg1);
		
		//printf("%s \n", opt);
		
		if(strcmp(opt, ")") != 0 && strstr(opt, "content") != NULL)
		{
			
			strcpy(rules_ds[ind].idso.type2, strtok(opt, ":"));
			strcpy(rules_ds[ind].idso.msg2, strtok(NULL, "\";"));

			//printf("%s\n", rules_ds[ind].idso.msg2);
		}
		else
		{
			strcpy(rules_ds[ind].idso.type2, "NULL");
			strcpy(rules_ds[ind].idso.msg2, "NULL");
			//printf("%s\n", rules_ds[ind].idso.msg2);
		}
		
		
		ind++;
	}

}


void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	ETHER_Frame* custom_frame = (ETHER_Frame*) calloc(1, sizeof(ETHER_Frame));
	
	//Remplissage Struct Frame
	populate_packet_ds(header, packet, custom_frame);
	
	//Appel au Matcher
	rule_matcher((Rule*) args, custom_frame);
	
	free(custom_frame);
}

int main(int argc, char* argv[]) 
{

	//preparation de read_rules
	FILE* file = fopen(argv[1], "r");

	char c;
	int count = 1;
	while ((c=fgetc(file)) != EOF)
	{
		if(c == '\n')
		{
			count++;
		}
	}

	fclose(file);

	Rule* rules_ds = (Rule*) calloc(count, sizeof(Rule));
	
	rules_ds[0].totalRules = count;

	file = fopen(argv[1], "r");
	
	//printf("pre_read_rules\n");

	read_rules(file, rules_ds, count);
	
	//printf("post_read_rules\n");

	//ecoute de l'interface eht0 ; credits : devdungeon
        char* device = "eth1";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t* handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle, 10);
        pcap_activate(handle);
        int total_packet_count = 0;

	//loop de l'ecoute des paquets
        pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*) rules_ds);

        return 0;
}
