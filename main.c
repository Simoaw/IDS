#include <stdlib.h>
#include "populate.h"

struct ids_rule
{
	char type_rule[10];
	char protocol[10];
	char address_source[IP_ADDR_LEN_STR];
	int port_source;
	char direction[3];
	char address_destination[IP_ADDR_LEN_STR];
	int port_destination;
	char options[150];
	
} typedef Rule;

void rule_matcher(Rule* rules_ds, ETHER_Frame* frame)
{
}


void read_rules(FILE* file, Rule* rules_ds, int count)
{
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

		token = strtok(NULL, " ");
		strcpy(rules_ds[ind].options, token);

		ind++;
	}
}


void my_packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	ETHER_Frame* custom_frame = (ETHER_Frame*) calloc(1, sizeof(ETHER_Frame));
	populate_packet_ds(header, packet, custom_frame);
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

	read_rules(file, rules_ds, count);

	printf("%d\n", rules_ds[0].port_source);

	//ecoute de l'interface eht0
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
