/**
 * \file
 * \brief main l2 agent functionality implemented here
 *
 * This is the main implementation of a level 2 agent (LLDP/HTIP) and extended level 2 agent
 * (LLDP/HTIP over GRE).
 */

#include <stdlib.h>
#include <string.h>
#include <lwip/opt.h>
#include <lwip/def.h>
#include <lwip/tcpip.h>
#include <lwip/netif.h>

#include "htip_tasks.h"
#include "packetbuild.h"
#include "l2agent.h"

#define ETHLLDP ntohs(0x88CC)

#ifndef ENET_MAC
#define ENET_MAC { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }
#endif

/* default information for the frames */
char * portDescription = "IEEE802.3";
char * deviceCategory = "jaist prototype";
char * manufacturerCode = "123456";
char * modelName = "esp32 prototype";
char * modelNumber = "esp32_0001";
char * status = "OK";

uint8_t communicationError = 0;
uint8_t channelUseState = 2;
uint8_t signalStrength = 80;
uint8_t sendInterval = 10;
uint8_t ttl = 3;

/**< the hard-coded mac for all outgoing htip frames */
uint8_t MAC_SRC[6] = ENET_MAC;

/**
 * Example of a function that generates an HTIP frame. Mimic this function in order
 * to generate your own HTIP frames
 * @param ttl only the Time to live as a parameter, everything else is static
 * @return a frame pointer that contains the raw LLDP frame, including the ethernet header
 */

PACKET_PTR generateHtipFrame(struct netif * iface) {
	const uint8_t MAC_DST[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	const uint16_t ethlldp = ETHLLDP;

	PACKET_PTR p = allocatePacket();
//push ethernet header

	pPokeMany(p, MAC_DST, sizeof(MAC_DST));
	pPokeMany(p, iface->hwaddr, iface->hwaddr_len);
	pPokeMany(p, (const uint8_t *) &ethlldp, 2);

//LLDP fields
	createChasisIDTLV(p, 4, MAC_SRC, sizeof(MAC_SRC));
	createPortIDTLV(p, 1, (uint8_t *) iface->name, sizeof(iface->name));
	createTTLTLV(p, ttl);
	createPortDescriptionTLV(p, (uint8_t *) portDescription,
			strlen(portDescription));

//htip fields
	createDeviceCategoryTLV(p, (uint8_t *) deviceCategory,
			strlen(deviceCategory));
	createManufacturerCodeTLV(p, (uint8_t *) manufacturerCode);
	createModelNameTLV(p, (uint8_t *) modelName, strlen(modelName));
	createModelNumberTLV(p, (uint8_t *) modelNumber, strlen(modelNumber));

	//EXTENDED STUFF
	createChannelUseStateTLV(p, channelUseState);
	createSignalStrengthTLV(p, signalStrength);
	createCommunicationErrorTLV(p, communicationError);

	createStatusInformationTLV(p, strlen(status), (uint8_t *) status);
	createLLDPDUSendInterval(p, sendInterval);

	/*
	 MACFTLV macf;
	 memset(&macf, 0, sizeof(MACFTLV));
	 macf.ifLength = 1;
	 macf.ifType = 6;
	 macf.macLength = 4;
	 uint8_t macs[] = { '\xAA', '\xAA', '\xAA', '\xAA', '\xAA', '\xAA',
	 '\xAA', '\x99', '\x99', '\x99', '\x99', '\x99', '\x99', '\x99',
	 '\x88', '\x88', '\x88', '\x88', '\x88', '\x88', '\x88', '\x77',
	 '\x77', '\x77', '\x77', '\x77', '\x77', '\x77', };
	 macf.macs = macs;
	 macf.portLength = 1;
	 macf.portNumber = 5;
	 createMacForwardingTLVstruct(p, &macf);
	 //second port
	 macf.portNumber = 9;
	 macf.macLength = 1;
	 uint8_t macs2[] = { '\x22', '\x22', '\x22', '\x44', '\x44', '\x44' };
	 macf.macs = macs2;
	 createMacForwardingTLVstruct(p, &macf);
	 */
//end field
	createLastTLV(p);
	return p;
}

/**
 * This is an example for generating a GRE/HTIP frame.
 * @param ttl only the Time to live as a parameter, everything else is static
 * @return a frame pointer that contains the raw LLDP frame, including the ethernet header, ready to be sent over GRE
 */
PACKET_PTR generateExtendedFrameTest(uint16_t ttl) {

	const uint8_t MAC_DST[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	const uint16_t ethtype = ETHLLDP;

	PACKET_PTR p = allocatePacket();
//push ethernet header

	pPokeMany(p, MAC_DST, sizeof(MAC_DST));	//not really used here but has to be here either way
	pPokeMany(p, MAC_SRC, sizeof(MAC_SRC));
	pPokeMany(p, (const uint8_t *) &ethtype, 2);
//LLDP fields
	uint8_t chasisId[] = "fake chasis id";
	createChasisIDTLV(p, 7, chasisId, sizeof(chasisId));
	uint8_t portId[] = "fake port id";
	createPortIDTLV(p, 7, portId, sizeof(portId));
	createTTLTLV(p, ttl);
	uint8_t portDesc[] = "IEEE802.3";
	createPortDescriptionTLV(p, portDesc, sizeof(portDesc));
//htip fields
	uint8_t devCat[] = "fake category";
	uint8_t manCode[] = "123456";
	uint8_t modelName[] = "fake model name";
	uint8_t modelNumber[] = "33445566778899";

	createDeviceCategoryTLV(p, devCat, sizeof(devCat));
	createManufacturerCodeTLV(p, manCode);
	createModelNameTLV(p, modelName, sizeof(modelName));
	createModelNumberTLV(p, modelNumber, sizeof(modelNumber));
	createChannelUseStateTLV(p, 16);
	createSignalStrengthTLV(p, 32);
	createCommunicationErrorTLV(p, 64);
	const char * status = "RANDOM STATUS";
	createStatusInformationTLV(p, strlen(status), (const uint8_t *) status);
	createLLDPDUSendInterval(p, 128);

	TLV_PTR extCon = startExtendConnnectivityInformation(p);
	uint8_t portLength = 1;
	uint32_t portNum = 24;
	uint8_t macLength = 12;
	uint8_t macNum = 2;
	uint8_t perHostInfo = 2;
	int8_t ss[] = { 75, -1 };
	int8_t ep[] = { 4, 101 };
	uint8_t channelInfo[] = { 16, 32, 100 };

	uint8_t * macs[] =
			{ (uint8_t *) "CCCCCCCCCCCC", (uint8_t *) "121212121212" };

	addExtendedPortAndMacInfo(extCon, portLength, portNum, macLength, macNum,
			perHostInfo);
	for (int i = 0; i < 2; i++) {
		addPerHostInfo(extCon, macLength, macs[i], ss[i], ep[i]);
	}
	addPerPortInfoNumber(extCon, 2);
	addPerPortPairedMacs(extCon, 2, 12, macs);
	addPerPortChannelInfo(extCon, 3, channelInfo);
	endExtendedTlv(extCon);

	TLV_PTR emac = startExtendMacTlv(p, 2);
	addExtendedMac(emac, 4, (uint8_t *) "4444");
	addExtendedMac(emac, 10, (uint8_t *) "AAAAAAAAAA");
	endExtendedTlv(emac);
	/*
	 MACFTLV macf;
	 memset(&macf, 0, sizeof(MACFTLV));
	 macf.ifLength = 1;
	 macf.ifType = 6;
	 macf.macLength = 4;
	 uint8_t macs [] = {
	 '\xAA', '\xAA', '\xAA', '\xAA', '\xAA', '\xAA', '\xAA',
	 '\x99', '\x99', '\x99', '\x99', '\x99', '\x99', '\x99',
	 '\x88', '\x88', '\x88', '\x88', '\x88', '\x88', '\x88',
	 '\x77', '\x77', '\x77', '\x77', '\x77', '\x77', '\x77',
	 };
	 macf.macs = macs;
	 macf.portLength = 1;
	 macf.portNumber = 5;
	 createMacForwardingTLVstruct(p, &macf);
	 //second port
	 macf.portNumber = 9;
	 macf.macLength = 1;
	 uint8_t macs2 [] = {
	 '\x22', '\x22', '\x22', '\x44', '\x44', '\x44'
	 };
	 macf.macs = macs2;
	 createMacForwardingTLVstruct(p, &macf);
	 //end field
	 *
	 */
	createLastTLV(p);
	return p;
}

/**
 * This is what I think should be an ideal just-send-the-packet
 * type of function.
 */
err_t iface_send(struct netif *netif, PACKET_PTR packet) {
	LOCK_TCPIP_CORE();
	struct pbuf * lowpacket = pbuf_alloc(PBUF_RAW_TX,
			packet->control.dataoffset, PBUF_REF);
	lowpacket->payload = packet->data;
	err_t result = netif->linkoutput(netif, lowpacket);
	pbuf_free(lowpacket);
	UNLOCK_TCPIP_CORE();
	return result;
}

/**
 * main HTIP Agent task here
 *
 * Registers the LLDP handler function and also sends generated HTIP frames
 */
void l2agent() {
	printf("SEND task started\n");
	//setup MAC_SRC outgoing source mac address
	//just grab the default interface and copy six bytes
	memcpy(MAC_SRC, netif_default->hwaddr, 6);

	err_t sendstatus;
	PACKET_PTR packet;

#define NETFLAGS (NETIF_FLAG_UP | NETIF_FLAG_BROADCAST | NETIF_FLAG_LINK_UP | NETIF_FLAG_ETHARP)
	while (1) {

		for (struct netif * iface = netif_default; iface != NULL;
				iface = iface->next) {
			//check that we have an ethernet device that uses arp, its up, linkup and does broadcasting
			if (NETFLAGS == (iface->flags & NETFLAGS)) {

				/* generate the htip frame */
				packet = generateHtipFrame(iface);

				/* actually sending the frame here */
				for (int j = 0; j < 3; j++) {
					//burst send 3 packets, for testing
					sendstatus = iface_send(iface, packet);
					printf("Sent HTIP! status: %d\r\n", sendstatus);
				}

				freePacket(packet);
			}
		}

		//update after half of the time has elapsed
		vTaskDelay(sendInterval * 1000 / portTICK_PERIOD_MS);
	}

}

