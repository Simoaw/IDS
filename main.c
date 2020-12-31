#include <stdlib.h>
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
	
} typedef Rule;

void rule_matcher(Rule* rules_ds, ETHER_Frame* frame)
{
	if(strcmp(rules_ds->address_source,"any") == 0||strcmp(rules_ds->address_source, frame->data.source_ip) == 0)
	{
		if(rules_ds->port_source == 0||rules_ds->port_source == frame->data.data.source_port)
		{
			if(strcmp(rules_ds->direction,"->") == 0)
			{
				if(strcmp(rules_ds->address_destination,"any") == 0||strcmp(rules_ds->address_destination,frame->data.destination_ip) == 0)
				{
					if(rules_ds->port_destination == 0||rules_ds->port_destination == frame->data.data.destination_port)
					{
						if(strcmp(rules_ds->protocol, frame->protocol) == 0)
						{
							/*if()
							{
												
							printf("Le paquet enfreint une regle\n");
		
							char rule_message[250];
							strcpy(rule_message,"Pas de message dans le fichier de regles.");

							if()
							{
							}

							if(strcmp(rules_ds->type_rule, "alert") == 0)
							{
								openlog("IDS",LOG_PID|LOG_CONS,LOG_USER);
								syslog(LOG_INFO,rule_message);
								closelog();
							}*/
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
		char* token = strtok(tmp_line, " ");

		strcpy(rules_ds[ind].type_rule, token);

		token = strtok(NULL, " ");
		strcpy(rules_ds[ind].protocol, token);

		token = strtok(NULL, " ");
		strcpy(rules_ds[ind].address_source, token);

		token = strtok(NULL, " ");
		rules_ds[ind].port_source = atoi(token);

		token = strtok(NULL, " ");
		strcpy(rules_ds[ind].direction, token);

		token = strtok(NULL, " ");
		strcpy(rules_ds[ind].address_destination, token);

		token = strtok(NULL, " ");
		rules_ds[ind].port_destination = atoi(token);

		token = strtok(NULL, "(:");
		strcpy(rules_ds[ind].idso.type1, token);

		token = strtok(NULL, "\"");
		printf("%s\n", token);
		strcpy(rules_ds[ind].idso.msg1, token);

		token = strtok(NULL, "; )");
		
		printf("%s\n", token);
		
		if(token != NULL)
		{
			token = strtok(NULL, ":");
		
			strcpy(rules_ds[ind].idso.type2, token);
			
			printf("%s\n", token);

			//token = strtok(NULL, "\"");
			strcpy(rules_ds[ind].idso.msg2, token);
		}

		ind++;
	}
	
	printf("%d", ind);

	//printf("%s - %s - %s - %d - %s - %d\n",rules_ds[0].type_rule, rules_ds[0].protocol, rules_ds[0].address_source, rules_ds[0].port_source, rules_ds[0].address_destination, rules_ds[0].port_destination);
}


void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	ETHER_Frame* custom_frame = (ETHER_Frame*) calloc(1, sizeof(ETHER_Frame));
	populate_packet_ds(header, packet, custom_frame);
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

	printf("%d\n", count);

	Rule* rules_ds = (Rule*) calloc(count, sizeof(Rule));

	file = fopen(argv[1], "r");
	
	printf("avant\n");

	read_rules(file, rules_ds, count);
	
	printf("apres\n");

	printf("%s\n", rules_ds[0].protocol);

	//ecoute de l'interface eht0 ; credits : devdungeon
        char* device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t* handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle, 10);
        pcap_activate(handle);
        int total_packet_count = 10;

	//loop de l'ecoute des paquets
        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;
}
