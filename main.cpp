#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

typedef struct ipHisto {
	char ip[20];
	int howmany = 0;
};
typedef struct arp {
	char sourceIP[20], targetIP[20], sourceMAC[30], targetMAC[30];
	int op;
	int ramec;
	int replyFlag = 0;
};
typedef struct icmp {
	char sourceIP[20], targetIP[20], message[100];
	int ramec;
	int replyFlag = 0;
};
typedef struct tcp {
	int sourcePort, targetPort;
	int ramec, flags;
};

int pkt_order = 1;
char errbuf[PCAP_ERRBUF_SIZE];

int histIndex = 0;
int arpIndex = 0;
int icmpIndex = 0;
int tcpIndex = 0;
int tftpIndex = 0;
int tftpFlag = 0;

ipHisto histogram[100000];
arp savedArps[100000];
icmp savedICMPs[100000];
tcp savedTCPs[100000];
int tftpOrd[100000];
int tftpPorts[2];

void forEveryPacket(u_char*, const struct pcap_pkthdr*, const u_char*);

void printAdresses(const u_char* pkt_data, FILE** file) {
	fprintf(*file, "Source MAC adress: %.2x %.2x %.2x %.2x %.2x %.2x\n", pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
	fprintf(*file, "Destination MAC adress: %.2x %.2x %.2x %.2x %.2x %.2x\n", pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5]);

}
void workTCP(const u_char* pkt_data, FILE** output, int IPv_size) {
	int tcpStart = 14 + IPv_size;
	fprintf(*output, "Source port: %d\n", pkt_data[tcpStart] * 256 + pkt_data[tcpStart + 1]);
	fprintf(*output, "Destination port: %d\n", pkt_data[tcpStart + 2] * 256 + pkt_data[tcpStart + 3]);

	FILE* tcpPorts = fopen("./TCPports.txt", "r");
	char nested[40] = "", line[40] = "", val[40] = "";
	//+12
	savedTCPs[tcpIndex].ramec = pkt_order - 1;
	savedTCPs[tcpIndex].sourcePort = pkt_data[tcpStart] * 256 + pkt_data[tcpStart + 1];
	savedTCPs[tcpIndex].targetPort = pkt_data[tcpStart + 2] * 256 + pkt_data[tcpStart + 3];
	savedTCPs[tcpIndex].flags = pkt_data[tcpStart + 13];
	tcpIndex++;

	while (fgets(line, 40, tcpPorts)) {
		sscanf(line, "%s %s", val, nested);
		if (pkt_data[tcpStart + 2] * 256 + pkt_data[tcpStart + 3] == atoi(val)
			|| pkt_data[tcpStart] * 256 + pkt_data[tcpStart + 1] == atoi(val))
			break;
	}
	fprintf(*output, "%s\n", nested);

	fclose(tcpPorts);
}
void tcpPairs() {
	FILE* tcpP = fopen("./tcpPairs.txt", "w");
	int comC = 1;

	for (int i = 0; i < tcpIndex; i++) {
		if (savedTCPs[i].flags == 2) {
			fprintf(tcpP, "Komunikacia %d\nRamec %d\n", comC++, savedTCPs[i].ramec);
			for (int j = i + 1; j < tcpIndex; j++) {
				if (savedTCPs[i].sourcePort == savedTCPs[j].sourcePort ||
					savedTCPs[i].sourcePort == savedTCPs[j].targetPort) {
					fprintf(tcpP, "Ramec %d\n", savedTCPs[j].ramec);
				}
			}
		}
	}

	fclose(tcpP);
}
void workUDP(const u_char* pkt_data, FILE** output, int IPv_size) {
	int udpStart = 14 + IPv_size;
	fprintf(*output, "Source port: %d\n", pkt_data[udpStart] * 256 + pkt_data[udpStart + 1]);
	fprintf(*output, "Destination port: %d\n", pkt_data[udpStart + 2] * 256 + pkt_data[udpStart + 3]);

	FILE* udpPorts = fopen("./UDPports.txt", "r");
	char nested[40] = "", line[40] = "", val[40] = "";

	while (fgets(line, 40, udpPorts)) {
		sscanf(line, "%s %s", val, nested);
		if (pkt_data[udpStart + 2] * 256 + pkt_data[udpStart + 3] == atoi(val))
			break;
	}

	if (!strcmp(nested, "tftp") && tftpFlag == 0) {
		tftpPorts[0] = pkt_data[udpStart] * 256 + pkt_data[udpStart + 1];
		tftpFlag = 1;
		tftpOrd[tftpIndex] = pkt_order - 1;
		tftpIndex++;
	}
	if (tftpFlag == 1 && pkt_data[udpStart + 2] * 256 + pkt_data[udpStart + 3] == tftpPorts[0]) {
		tftpPorts[1] = pkt_data[udpStart] * 256 + pkt_data[udpStart + 1];
		tftpFlag = 2;
		tftpOrd[tftpIndex] = pkt_order - 1;
		tftpIndex++;
	}
	else if (tftpFlag == 2 &&(
		pkt_data[udpStart + 2] * 256 + pkt_data[udpStart + 3] == tftpPorts[0] &&
		pkt_data[udpStart] * 256 + pkt_data[udpStart + 1] == tftpPorts[1] ||
		pkt_data[udpStart + 2] * 256 + pkt_data[udpStart + 3] == tftpPorts[1] &&
		pkt_data[udpStart] * 256 + pkt_data[udpStart + 1] == tftpPorts[0])) {
		strcpy(nested, "TFTP");
		tftpOrd[tftpIndex] = pkt_order - 1;
		tftpIndex++;

	}
	fprintf(*output, "%s\n", nested);

	fclose(udpPorts);
}
void tftpPairs() {
	FILE* tftpCom = fopen("./tftpCom.txt", "w");
	for (int i = 0; i < tftpIndex; i++) {
		fprintf(tftpCom, "Ramec %d\n", tftpOrd[i]);
	}
	fclose(tftpCom);
}
void workARP(const u_char* pkt_data) {
	savedArps[arpIndex].op = pkt_data[21];
	sprintf(savedArps[arpIndex].sourceMAC, "%x:%x:%x:%x:%x:%x", pkt_data[22], pkt_data[23], pkt_data[24], pkt_data[25], pkt_data[26], pkt_data[27]);
	sprintf(savedArps[arpIndex].sourceIP, "%d.%d.%d.%d", pkt_data[28], pkt_data[29], pkt_data[30], pkt_data[31]);
	sprintf(savedArps[arpIndex].targetMAC, "%x:%x:%x:%x:%x:%x", pkt_data[32], pkt_data[33], pkt_data[34], pkt_data[35], pkt_data[36], pkt_data[37]);
	sprintf(savedArps[arpIndex].targetIP, "%d.%d.%d.%d", pkt_data[38], pkt_data[39], pkt_data[40], pkt_data[41]);
	arpIndex++;
}
void arpPairs() {
	FILE* arpP = fopen("./ArpPairs.txt", "w");
	int comC = 1, flag = 0;

	for (int i = 0; i < arpIndex; i++) {
		flag = 0;
		for (int j = i+1; j < arpIndex; j++) {
			if (savedArps[i].op == 1 && savedArps[j].op == 2
				&& !strcmp(savedArps[i].targetIP, savedArps[j].sourceIP)
				&& !strcmp(savedArps[j].targetIP, savedArps[i].sourceIP)) {
				fprintf(arpP, "Komunikacia %d UPLNA\n", comC++);
				fprintf(arpP, "Ramec %d a %d\n", savedArps[i].ramec, savedArps[j].ramec);
				savedArps[j].replyFlag = 1;
				flag = 1;
			}
		}
		if (!flag && savedArps[i].op == 1) {
			fprintf(arpP, "Komunikacia %d NEUPLNA\n", comC++);
			fprintf(arpP, "Ramec %d\n", savedArps[i].ramec);
		}
	}
	for (int i = 0; i < arpIndex; i++) {
		if (!savedArps[i].replyFlag && savedArps[i].op == 2) {
			fprintf(arpP, "Komunikacia %d NEUPLNA LONE REPLY\n", comC++);
			fprintf(arpP, "Ramec %d\n", savedArps[i].ramec);
		}
	}
	fclose(arpP);
}
void workICMP(const u_char* pkt_data, FILE** output, int IPv_size) {
	int icmpStart = 14 + IPv_size;

	FILE* tcpPorts = fopen("./icmpTypes.txt", "r");
	char nested[40] = "", line[40] = "", val[40] = "";

	while (fgets(line, 40, tcpPorts)) {
		sscanf(line, "%s %s", val, nested);
		if (pkt_data[icmpStart] == atoi(val))
			break;
	}
	fprintf(*output, "%s\n", nested);
	strcpy(savedICMPs[icmpIndex].message, nested);
	savedICMPs[icmpIndex].ramec = pkt_order - 1;
	icmpIndex++;
}
void icmpPairs() {
	FILE* icmpP = fopen("./icmpPairs.txt", "w");
	int comC = 1, flag = 0;

	for (int i = 0; i < icmpIndex; i++) {
		flag = 0;
		for (int j = i + 1; j < icmpIndex; j++) {
			if (!strcmp(savedICMPs[i].targetIP, savedICMPs[j].sourceIP) && !strcmp(savedICMPs[i].message, "Echo")) {
				fprintf(icmpP, "Komunikacia %d UPLNA\n", comC++);
				fprintf(icmpP, "Ramec %d a %d\n", savedICMPs[i].ramec, savedICMPs[j].ramec);
				savedICMPs[j].replyFlag = 1;
				flag = 1;
				break;
			}
			else
				break;
		}
		if (!flag && !savedICMPs[i].replyFlag) {
			fprintf(icmpP, "Komunikacia %d NEUPLNA\n", comC++);
			fprintf(icmpP, "Ramec %d\n", savedICMPs[i].ramec);
		}
	}

	fclose(icmpP);
}

void workIPv4(const u_char* pkt_data, FILE** output) {
	FILE* protocols = fopen("./protocols.txt", "r");
	char nested[40] = "", line[40] = "", val[40] = "";
	char sourceIP[20], destIP[20];
	int flag = 0;
	//23

	while (fgets(line, 40, protocols)) {
		sscanf(line, "%s %s", val, nested);
		if (pkt_data[23] == atoi(val))
			break;
	}
	sprintf(sourceIP, "%d.%d.%d.%d", pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]);
	fprintf(*output, "Source IP: %s\n", sourceIP);
	sprintf(destIP, "%d.%d.%d.%d", pkt_data[30], pkt_data[31], pkt_data[32], pkt_data[33]);
	fprintf(*output, "Destination IP: %s\n", destIP);
	fprintf(*output, "%s\n", nested);

	for (int i = 0; i < histIndex; i++) {
		if (!strcmp(destIP, histogram[i].ip)) {
			histogram[i].howmany++;
			flag = 1;
			break;
		}
	}
	if (!flag) {
		histogram[histIndex].howmany = 1;
		sprintf(histogram[histIndex].ip, destIP);
		histIndex++;
	}
	
	//Get stuff related to TCP and UDP sorted
	if (!strcmp(nested, "TCP")) {
		workTCP(pkt_data, output, (pkt_data[14] - 64) * 4);
	}
	else if (!strcmp(nested, "UDP")) {
		workUDP(pkt_data, output, (pkt_data[14] - 64) * 4);
	}
	else if (!strcmp(nested, "ICMP")) {
		strcpy(savedICMPs[icmpIndex].sourceIP, sourceIP);
		strcpy(savedICMPs[icmpIndex].targetIP, destIP);
		workICMP(pkt_data, output, (pkt_data[14] - 64) * 4);
	}

	fclose(protocols);
}

int main() {
	pcap_t* fil;
	char filename[50];	//For future interactive use

	//Clears the file 
	FILE* output;
	output = fopen("./leOutput.txt", "w");
	fclose(output);


	char inp[50], inpFin[100];
	printf("Zadajte nazov suboru\n");
	scanf("%s", &inp);
	sprintf(inpFin, ".\\vzorky_pcap_na_analyzu\\%s", inp);
	//Open pcap
	if ((fil = pcap_open_offline(inpFin, errbuf)) == NULL) {
		printf("Cant open it");
		return -1;
	}

	//Run functionality on every packet
	pcap_loop(fil, 0, forEveryPacket, NULL);


	//IPv4 counter
	output = fopen("./leOutput.txt", "a");
	int max = histogram[0].howmany;
	for (int i = 0; i < histIndex; i++) {
		fprintf(output, "%s\n", histogram[i].ip);
		if (histogram[i].howmany > max)
			max = histogram[i].howmany;
	}

	for (int i = 0; i < histIndex; i++) {
		if (histogram[i].howmany == max) {
			fprintf(output, "IP %s accepted %d packets", histogram[i].ip, histogram[i].howmany);
			break;
		}
	}

	//ARP pair function
	arpPairs();
	icmpPairs();
	tftpPairs();
	tcpPairs();

	//Close pcap
	pcap_close(fil);
	fclose(output);
}

void forEveryPacket(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	//Open file stream
	int len;
	char nested[40] = "", line[40] = "", val[40] = "";

	if (header->caplen > 60)
		len = header->caplen;
	else
		len = 60;
	FILE* output;
	output = fopen("./leOutput.txt", "a");

	fprintf(output, "Ramec %d\n", pkt_order++);
	fprintf(output, "frame length given by pcap API -%d B\n", header->caplen);
	fprintf(output, "frame length carried through media -%d B\n", len + 4);

	//If the packet is ethernet
	if (pkt_data[12] * 256 + pkt_data[13] > 1500) {
		FILE* eTypes = fopen("./ethertypes.txt", "r");	//Open list of ethertypes
		fprintf(output, "Ethernet II\n");
		printAdresses(pkt_data, &output);
			
		while (fgets(line, 40, eTypes)) {
			sscanf(line, "%s %s", val, nested);
			if (pkt_data[12] * 256 + pkt_data[13] == atoi(val))
				break;
		}
		fprintf(output, "%s\n", nested);
		fclose(eTypes);

		//printf("ramec %d\n", pkt_order-1);
		//If IPv4
		if (!strcmp(nested, "IPv4"))
			workIPv4(pkt_data, &output);
		else if (!strcmp(nested, "ARP")) {
			workARP(pkt_data);
			savedArps[arpIndex - 1].ramec = pkt_order - 1;
			if(savedArps[arpIndex - 1].op == 1)
				fprintf(output, "Request\n");
			else if(savedArps[arpIndex - 1].op == 2)
				fprintf(output, "Reply\n");
			fprintf(output, "Source IP: %s\n", savedArps[arpIndex - 1].sourceIP);
			fprintf(output, "Source MAC: %s\n", savedArps[arpIndex - 1].sourceMAC);
			fprintf(output, "Dest IP: %s\n", savedArps[arpIndex - 1].targetIP);
			fprintf(output, "Dest MAC: %s\n", savedArps[arpIndex - 1].targetMAC);
		}
		
			
	}
	//If packet is IEEE 802.3
	else {
		FILE* ieees = fopen("./ieees.txt", "r");
		fprintf(output, "IEEE 802.3\n");

		while (fgets(line, 40, ieees)) {
			sscanf(line, "%s %s", val, nested);
			if (pkt_data[14] * 256 + pkt_data[15] == atoi(val))
				break;
		}
		fprintf(output, "%s\n", nested);
		//printf("Ramec %d| val: %d| nest: %s | line: %s\n", pkt_order - 1, atoi(val), nested, line);
		printAdresses(pkt_data, &output);
		fclose(ieees);
	}

	//Writes the hex string of the packet 
	for (int i = 1; i <= len; i++) {
		fprintf(output, "%.2x ", pkt_data[i - 1]);
		if (!(i % 16))
			fprintf(output, "\n");
	}

	fprintf(output, "\n\n");
	fclose(output);
}