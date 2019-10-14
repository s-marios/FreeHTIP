#include <stdlib.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "packetbuild.h"

/////////////////////////////////////////
// Frame creation related functions here
/////////////////////////////////////////

PACKET_PTR allocatePacket() {
	size_t initsize = 1500;
	PACKET_PTR packet = (PACKET_PTR) malloc(initsize);
	if (packet != NULL) {
		//we have a successful allocation
		//setup fields
		memset(packet, 0, initsize);
		//what is this?!
		packet->control.allocated = initsize - (sizeof(PACKET));
		packet->data = (uint8_t *) packet + (sizeof(PACKET));
	}
	return packet;
}

void freePacket(PACKET_PTR packet) {
	free(packet);
}

PACKET_PTR pPoke(PACKET_PTR packet, uint8_t achar) {
	packet->data[packet->control.dataoffset++] = achar;
	return packet;
}

PACKET_PTR pPokeMany(PACKET_PTR packet, const uint8_t * data, size_t length) {
	memcpy(&packet->data[packet->control.dataoffset], data, length);
	packet->control.dataoffset += length;
	return packet;
}

TLV_PTR initTLV(PACKET_PTR packet, uint8_t type) {
	TLV_PTR tlv = malloc(sizeof(TLV));
	if (tlv) {
		tlv->type = type;
		tlv->datastart = packet->control.dataoffset;
		tlv->packet = pPokeMany(packet, (uint8_t *) "\x00\x00", 2);
	}
	return tlv;
}

TLV_PTR parseFromData(uint8_t * data) {
	TLV_PTR tlv = malloc(sizeof(TLV));
	if (tlv) {
		tlv->type = parseTLVType(data);
		tlv->size = parseTLVLength(data);
		tlv->data = data;
	}
	return tlv;
}

TLV_PTR tlvPokeMany(TLV_PTR tlv, const uint8_t * data, size_t length) {
	tlv->packet = pPokeMany(tlv->packet, data, length);
	return tlv;
}

TLV_PTR tlvPoke(TLV_PTR tlv, uint8_t achar) {
	tlv->packet = pPoke(tlv->packet, achar);
	return tlv;
}

TLV_PTR finalizeTLV(TLV_PTR tlv) {
//compute size
//the -2 is for the two header bytes
	tlv->size = tlv->packet->control.dataoffset - tlv->datastart - 2;
	tlv->size &= 0x01FF;
//set up size on the original buffer
	uint16_t * first = (uint16_t *) &tlv->packet->data[tlv->datastart];
	(*first) = htons(tlv->size);

//set up the tlv type
	tlv->packet->data[tlv->datastart] |= (tlv->type << 1);
	return tlv;
}

uint16_t getTLVLength(TLV_PTR tlv) {
	uint16_t * size_p = (uint16_t *) &tlv->packet->data[tlv->datastart];
	uint16_t length = ntohs((*size_p));
	return length & 0x01FF;
}

uint8_t getTLVType(TLV_PTR tlv) {
	uint8_t type = tlv->packet->data[tlv->datastart];
	return type >> 1;
}

uint16_t parseTLVLength(uint8_t * data) {
	uint16_t * size_p = (uint16_t *) data;
	uint16_t length = ntohs((*size_p));
	return length & 0x01FF;
}

uint8_t parseTLVType(uint8_t * data) {
	return data[0] >> 1;
}

void freeTLV(TLV_PTR tlv) {
	free(tlv);
}

void createLastTLV(PACKET_PTR packet) {
	TLV_PTR tlv = initTLV(packet, 0x0);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createChasisIDTLV(PACKET_PTR packet, uint8_t type, uint8_t * data,
		size_t length) {
	TLV_PTR tlv = initTLV(packet, 1);
//TODO check type in 0-7
	tlvPoke(tlv, type);
	tlvPokeMany(tlv, data, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createPortIDTLV(PACKET_PTR packet, uint8_t type, uint8_t * data,
		size_t length) {
	TLV_PTR tlv = initTLV(packet, 2);
//TODO check type in 0-7
	tlvPoke(tlv, type);
	tlvPokeMany(tlv, data, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createTTLTLV(PACKET_PTR packet, uint16_t ttl) {
	TLV_PTR tlv = initTLV(packet, 3);
	uint16_t toNetwork = htons(ttl);
	tlvPokeMany(tlv, (uint8_t *) &toNetwork, 2);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createPortDescriptionTLV(PACKET_PTR packet, uint8_t * data, size_t length) {
	TLV_PTR tlv = initTLV(packet, 4);
	tlvPokeMany(tlv, data, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createDeviceCategoryTLV(PACKET_PTR packet, uint8_t * deviveCategory,
		size_t length) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1); //subtype
	tlvPoke(tlv, 1); //device info id = 1;
//TODO length check
	tlvPoke(tlv, length);
	tlvPokeMany(tlv, deviveCategory, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createManufacturerCodeTLV(PACKET_PTR packet, uint8_t * manufacturerCode) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1); //subtype
	tlvPoke(tlv, 2); //device info id = man code;
//TODO length check == 6?
	tlvPoke(tlv, 6);
	tlvPokeMany(tlv, manufacturerCode, 6);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createModelNameTLV(PACKET_PTR packet, uint8_t * modelName, size_t length) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1); //subtype
	tlvPoke(tlv, 3); //device info id = model name = 3;
//TODO length check
	tlvPoke(tlv, length);
	tlvPokeMany(tlv, modelName, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}
void createModelNumberTLV(PACKET_PTR packet, uint8_t * modelNumber,
		size_t length) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1); //subtype
	tlvPoke(tlv, 4); //device info id = model name = 3;
//TODO length check <= 31
	tlvPoke(tlv, length);
	tlvPokeMany(tlv, modelNumber, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createOneByteTLV(PACKET_PTR packet, uint8_t id, uint8_t value) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1);
	tlvPoke(tlv, id);
	tlvPoke(tlv, 1); // one byte length
	uint8_t val = value;
	if (value > 100) {
		val = 100;
	}
	tlvPoke(tlv, val);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createMultiByteTLV(PACKET_PTR packet, uint8_t id, uint8_t size,
		const uint8_t * data) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1);
	tlvPoke(tlv, id);
	tlvPoke(tlv, size); // one byte length
	tlvPokeMany(tlv, data, size);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createChannelUseStateTLV(PACKET_PTR packet, uint8_t channelUsage) {
	createOneByteTLV(packet, 20, channelUsage);
}

void createSignalStrengthTLV(PACKET_PTR packet, uint8_t signalStrength) {
	createOneByteTLV(packet, 21, signalStrength);
}

void createCommunicationErrorTLV(PACKET_PTR packet, uint8_t error) {
	createOneByteTLV(packet, 22, error);
}

void createStatusInformationTLV(PACKET_PTR packet, uint8_t size,
		const uint8_t * data) {
	createMultiByteTLV(packet, 50, size, data);
}

void createLLDPDUSendInterval(PACKET_PTR packet, uint16_t interval) {
	uint16_t netbo = htons(interval);
	createMultiByteTLV(packet, 80, 2, (uint8_t *) &netbo);
}

void createDeviceInfoEXTTLV(PACKET_PTR packet, uint8_t * orgCode,
		uint8_t deviceInfoType, uint8_t * deviceInfo, uint8_t length) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 1);
	tlvPoke(tlv, 255);
	tlvPokeMany(tlv, (uint8_t *) orgCode, 6);
	tlvPoke(tlv, deviceInfoType);
	tlvPoke(tlv, length);
	tlvPokeMany(tlv, deviceInfo, length);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createMacForwardingTLV(PACKET_PTR packet, uint8_t * ifType,
		uint8_t ifLength, uint8_t * portNum, uint8_t portLength, uint8_t * macs,
		uint8_t macLength) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 2);
	tlvPoke(tlv, ifLength);
	switch (ifLength) {
	case 1:
		tlvPoke(tlv, ifType[0]);
		break;
	case 2: {
		uint16_t twobyte = htons(*ifType);
		tlvPokeMany(tlv, (uint8_t *) &twobyte, 2);
	}
		break;
	case 4: {
		uint32_t fourbyte = htonl(*ifType);
		tlvPokeMany(tlv, (uint8_t *) &fourbyte, 4);
	}
		break;
	default:
		//just copy whatever is there and pray
		tlvPokeMany(tlv, ifType, ifLength);
		break;
	}
	tlvPoke(tlv, portLength);
	tlvPokeMany(tlv, portNum, portLength);
	tlvPoke(tlv, macLength);
	tlvPokeMany(tlv, macs, macLength * 6);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

void createMacForwardingTLVstruct(PACKET_PTR packet, MACFTLV_PTR macf) {
	createMacForwardingTLV(packet, (uint8_t *) &macf->ifType, macf->ifLength,
			(uint8_t *) &macf->portNumber, macf->portLength, macf->macs,
			macf->macLength);
}

void createMacEtherBridge(PACKET_PTR packet, uint8_t * macs, uint8_t macLength) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 3);
	tlvPoke(tlv, macLength);
	tlvPokeMany(tlv, macs, macLength * 6);
	finalizeTLV(tlv);
	freeTLV(tlv);
}

//Extended

TLV_PTR startExtendMacTlv(PACKET_PTR packet, uint8_t numberOfMacs) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 5);
	tlvPoke(tlv, numberOfMacs);
	return tlv;
}

void addExtendedMac(TLV_PTR tlv, uint8_t length, uint8_t * mac) {
	tlvPoke(tlv, length);
	tlvPokeMany(tlv, mac, length);
}

void endExtendedTlv(TLV_PTR tlv) {
	finalizeTLV(tlv);
	freeTLV(tlv);
}

TLV_PTR startExtendConnnectivityInformation(PACKET_PTR packet) {
	TLV_PTR tlv = initTLV(packet, 127);
	tlvPokeMany(tlv, TTC_OUI, 3);
	tlvPoke(tlv, 4);
	return tlv;
}

void addExtendedPortAndMacInfo(TLV_PTR tlv, uint8_t portLength,
		uint32_t portNum, uint8_t macLength, uint8_t macNum,
		uint8_t perHostInfoNum) {
	tlvPoke(tlv, portLength);
	switch (portLength) {
	case 1: {
		uint8_t num8 = portNum;
		tlvPoke(tlv, num8);
	}
		break;
	case 2: {
		uint16_t num16 = portNum;
		tlvPokeMany(tlv, (uint8_t *) &num16, 2);
	}
		break;
	case 4:
		tlvPokeMany(tlv, (uint8_t *) &portNum, 4);
		break;
	}
	tlvPoke(tlv, macLength);
	tlvPoke(tlv, macNum);
	tlvPoke(tlv, perHostInfoNum);
}

void addPerHostInfo(TLV_PTR tlv, uint8_t macLength, uint8_t * mac,
		int8_t signalStrength, int8_t errorPercentage) {
	tlvPokeMany(tlv, mac, macLength);
	if (signalStrength < 0 || signalStrength > 100) {
		tlvPoke(tlv, 0);
	} else {
		tlvPoke(tlv, 1);
		tlvPoke(tlv, signalStrength);
	}

	if (errorPercentage < 0 || errorPercentage > 100) {
		tlvPoke(tlv, 0);
	} else {
		tlvPoke(tlv, 1);
		tlvPoke(tlv, errorPercentage);
	}
}

void addPerPortInfoNumber(TLV_PTR tlv, uint8_t infoNumbers) {
	tlvPoke(tlv, infoNumbers);
}

void addPerPortPairedMacs(TLV_PTR tlv, uint8_t macNums, uint8_t macLength,
		uint8_t ** macs) {
	if (macNums == 0 || macs == NULL) {
		tlvPoke(tlv, 0);
	} else {
		tlvPoke(tlv, macNums);
		for (int i = 0; i < macNums; i++) {
			tlvPokeMany(tlv, macs[i], macLength);
		}
	}
}

void addPerPortChannelInfo(TLV_PTR tlv, uint8_t channelNum,
		uint8_t * channelInfo) {
	if (channelNum == 0 || channelInfo == NULL) {
		tlvPoke(tlv, 0);
	} else {
		tlvPoke(tlv, channelNum);
		tlvPokeMany(tlv, channelInfo, channelNum);
	}
}
