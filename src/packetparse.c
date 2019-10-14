#include <stdlib.h>
#include <string.h>
#include <lwip/def.h>
#include "packetparse.h"
#include "packetbuild.h"

int isFromSameSourceEther(HTIPPAYLOAD_PTR htipnew, HTIPPAYLOAD_PTR htipold) {
	ETHHEADER_PTR headerOld = (ETHHEADER_PTR) htipnew->packet.data;
	ETHHEADER_PTR headerNew = (ETHHEADER_PTR) htipold->packet.data;
	return (memcmp(headerOld->SRC, headerNew->SRC, 6));
}

/////////////////////////////////////////////
// Parsing and Printing related functions
////////////////////////////////////////////

/** this relates to the parsing, be careful */
void setHTIPdata(HTIPPAYLOAD_PTR htip, size_t size, uint8_t * data) {
	htip->packet.data = malloc(size);
	if (htip->packet.data) {
		memcpy(htip->packet.data, data, size);
	}
	htip->packet.control.allocated = size;
	htip->packet.control.dataoffset = size;
}

int checkAgainstTLVSize(uint8_t index, TLV_PTR tlv) {
	return (int) tlv - index;
}

char parseHTIPSubtype4(TLV_PTR tlv, HTIPPAYLOAD_PTR htip) {
	uint8_t subtype = tlv->data[5];

	if (subtype != 4) {
		//bad things happened. TODO
		return -1;
	}
	uint8_t portLength = tlv->data[6];
	uint32_t portNumber = 0;
	uint8_t parseIndex = 6;
	switch (portLength) {
	case 1:
		portNumber = tlv->data[parseIndex];
		break;
	case 2: {
		uint16_t * pNum = (uint16_t *) &tlv->data[parseIndex];
		portNumber = ntohs(*pNum);
	}
		break;
	case 4: {
		uint32_t * pNum = (uint32_t *) &tlv->data[parseIndex];
		portNumber = ntohl(*pNum);
	}
		break;
	default:
		return -1;
	}
	parseIndex = 6 + portLength;
	uint8_t macLength = tlv->data[parseIndex++];
	uint8_t macNum = tlv->data[parseIndex++];
	uint8_t perHostInfos = tlv->data[parseIndex++];
	uint8_t ssLength;
	uint8_t ss; // signalStrength;
	uint8_t epLength;
	uint8_t ep; //error percentage;
//parsing macs, signal strengths and error percentages
	for (int i = 0; i < macNum; i++) {
		// TODO read mac address.
		parseIndex += macLength;
		ssLength = tlv->data[parseIndex++];
		if (ssLength > 0) {
			ss = tlv->data[parseIndex++];
		}
		epLength = tlv->data[parseIndex++];
		if (epLength > 0) {
			ep = tlv->data[parseIndex++];
		}
		if (checkAgainstTLVSize(parseIndex, tlv) > 0) {
			return -1;
		}
		if (perHostInfos > 2) {
			uint8_t length;
			//parse unknown stuff for the time being, just skip them
			length = tlv->data[parseIndex++];
			if (length > 0) {
				parseIndex += length;
			}

			if (checkAgainstTLVSize(parseIndex, tlv) > 0) {
				return -1;
			}

		}
	}
	uint8_t perPortInfos = tlv->data[parseIndex++];
	uint8_t perPortPairingNum = tlv->data[parseIndex++];

	if (checkAgainstTLVSize(parseIndex, tlv) > 0) {
		return -1;
	}

	for (int i = 0; i < perPortPairingNum; i++) {
		//TODO read paired mac addresses here
		parseIndex += macLength;
	}
	uint8_t channelLength = tlv->data[parseIndex++];
	uint8_t channelUsage = -1;
	if (channelLength > 0) {
		channelUsage = tlv->data[parseIndex++];
	}

	if (checkAgainstTLVSize(parseIndex, tlv) > 0) {
		return -1;
	}

//parse unknown per port infos
	if (perPortInfos > 2) {
		uint8_t length;
		//parse unknown stuff for the time being, just skip them
		length = tlv->data[parseIndex++];
		if (length > 0) {
			parseIndex += length;
		}

		if (checkAgainstTLVSize(parseIndex, tlv) > 0) {
			return -1;
		}

	}
//a check for seeing whether we parsed the thing successfully or not
	if (tlv->size == parseIndex) {
		return 0;
	}
	return 1;
}

void parseHTIPSpecific(TLV_PTR tlv, HTIPPAYLOAD_PTR htip) {
	uint8_t subtype = tlv->data[5];
	switch (subtype) {
	case 1: {
		uint8_t devInfo = tlv->data[6];
		uint8_t infoSize = tlv->data[7];
		uint8_t * infoData = &tlv->data[8];
		switch (devInfo) {
		case 1:
			htip->deviceCategory.size = infoSize;
			htip->deviceCategory.info = infoData;
			break;
		case 2:
			htip->manufacturerCode.size = infoSize;
			htip->manufacturerCode.info = infoData;
			break;
		case 3:
			htip->modelName.size = infoSize;
			htip->modelName.info = infoData;
			break;
		case 4:
			htip->modelNumber.size = infoSize;
			htip->modelNumber.info = infoData;
			break;
		default:
			//TODO add the rest optional subtype 1 tlvs
			break;
		}
	}
		return;	// case1 end
	case 2: //TODO mac info
	{
		MACFTLV_PTR * macftlvindex;
		//just get the last entry, and do nothing

		for (int i = 0; (macftlvindex = &htip->macftlvs[i]); i++) {
			if (i >= MAXPORTS) {
				return;
			}
			if ((*macftlvindex) == 0)
				break;
		}
		(*macftlvindex) = malloc(sizeof(MACFTLV));
		if (!(*macftlvindex)) {
			return;
		}
		MACFTLV_PTR macftlv = (*macftlvindex);
		memset(macftlv, 0, sizeof(MACFTLV));
		//parse interface type and length
		macftlv->ifLength = tlv->data[6];
		switch (macftlv->ifLength) {
		case 1:
			macftlv->ifType = tlv->data[7];
			break;
		case 2: {
			uint16_t * ifType = (uint16_t *) &tlv->data[7];
			macftlv->ifType = ntohs(*ifType);
		}
			break;
		case 4: {
			uint32_t * ifType = (uint32_t *) &tlv->data[7];
			macftlv->ifType = ntohl(*ifType);
		}
			break;
		default:
			return;
		}
		//parse port number and port length
		uint32_t index = 7 + macftlv->ifLength;
		macftlv->portLength = tlv->data[index];
		index++;
		switch (macftlv->portLength) {
		case 1:
			macftlv->portNumber = tlv->data[index];
			break;
		case 2: {
			uint16_t * portNumber = (uint16_t *) &tlv->data[index];
			macftlv->portNumber = ntohs(*portNumber);
		}
			break;
		case 4: {
			uint32_t * portNumber = (uint32_t *) &tlv->data[index];
			macftlv->portNumber = ntohl(*portNumber);
		}
			break;
		default:
			return;
		}
		index = 8 + macftlv->ifLength + macftlv->portLength;
		macftlv->macLength = tlv->data[index];
		index++;
		macftlv->macs = &tlv->data[index];
	}
		return;
	case 3:
		htip->macs.acount = tlv->data[6];
		htip->macs.info = &tlv->data[7];
		return;
	case 4:
		//this subtype... oh god...
		parseHTIPSubtype4(tlv, htip);
		return;
	case 5:
		htip->extMacs.acount = tlv->data[6];
		htip->extMacs.size = tlv->data[7];
		htip->extMacs.info = &tlv->data[8];
		return;
	default:
		return; //things i don't know, handle them
	}
}

HTIPPAYLOAD_PTR parseLLDP(HTIPPAYLOAD_PTR htip, uint8_t * indata,
		size_t inlength) {
	size_t next = 0;
	uint8_t normal = 0;
	uint8_t * data = indata;
	size_t length = inlength;
	if (htip->packet.data) {
		ETHHEADER_PTR ethheader = (ETHHEADER_PTR) htip->packet.data;
		htip->src.info = ethheader->SRC;
		htip->src.size = 6;
		//if the actual packet data is set prefer that over indata
		data = htip->packet.data + 14;
		length = htip->packet.control.allocated - 14;
	}
	while (next < length) {
		TLV_PTR tlv = parseFromData(&data[next]);
		if (tlv == NULL)
			return NULL;
		switch (tlv->type) {
		case 1:
			htip->chasisId.acount = tlv->data[2];
			htip->chasisId.info = &tlv->data[3];
			htip->chasisId.size = tlv->size - 1;
			break;
		case 2:
			htip->portId.acount = tlv->data[2];
			htip->portId.info = &tlv->data[3];
			htip->portId.size = tlv->size - 1;
			break;
		case 3: {
			uint16_t * ttlptr = (uint16_t *) &tlv->data[2];
			htip->ttl.acount = ntohs(*ttlptr);
			htip->ttl.info = 0;
			htip->ttl.size = 2;
		}
			break;
		case 4:
			htip->portDescription.info = &tlv->data[2];
			htip->portDescription.size = tlv->size;
			htip->portDescription.acount = 0;
			break;
		case 5:
		case 6:
		case 7:
		case 8:
			htip->parseResult.size += 1;
			break;
		case 0:
			normal = 1;
			freeTLV(tlv);
			goto PARSEEND;
		case 127:
			parseHTIPSpecific(tlv, htip);
			break;
		default:
			goto PARSEEND;
		}
		next += 2; //the size of a TLV header
		next += tlv->size;
		freeTLV(tlv);
	}
	PARSEEND: htip->parseResult.acount = normal;
	return htip;
}

void printHTIP(HTIPPAYLOAD_PTR htip, FILE * out) {
	fprintf(out, "LLDP REPORT\n");
	fprintf(out, "---------------\n");
	fprintf(out, "Parse result: %s\n",
			htip->parseResult.acount == 1 ? "GOOD" : "BAD");
	if (htip->parseResult.acount != 1) {
		fprintf(out, "bad packet picked up, stopping further processing\n");
		return;
	}
	fprintf(out, "Source MAC:");
	for (int i = 0; i < 6; i++) {
		fprintf(out, "%02x", htip->src.info[i]);
		if (i != 5) {
			fprintf(out, ":");
		} else {
			fprintf(out, "\n");
		}
	}
	fprintf(out, "  Chasis ID: ");
	fwrite(htip->chasisId.info, htip->chasisId.size, 1, out);
	fprintf(out, "\n  Chasis ID (type): %d", htip->chasisId.acount);
	fprintf(out, "\n  Port ID: ");
	fwrite(htip->portId.info, htip->portId.size, 1, out);
	fprintf(out, "\n  Port ID (type): %d", htip->portDescription.acount);
	fprintf(out, "\n  Time To Live: %d", htip->ttl.acount);
	fprintf(out, "\n  Port Description: ");
	fwrite(htip->portDescription.info, htip->portDescription.size, 1, out);

	fprintf(out, "\nHTIP REPORT");
	if (htip->deviceCategory.info != NULL) {
		fprintf(out, "\n  Device category: ");
		fwrite(htip->deviceCategory.info, htip->deviceCategory.size, 1, out);
	}
	if (htip->manufacturerCode.info != NULL) {
		fprintf(out, "\n  Manufacturer Code: ");
		fwrite(htip->manufacturerCode.info, htip->manufacturerCode.size, 1,
				out);
	}
	if (htip->modelName.info != NULL) {
		fprintf(out, "\n  Model Name: ");
		fwrite(htip->modelName.info, htip->modelName.size, 1, out);
	}
	if (htip->modelNumber.info != NULL) {
		fprintf(out, "\n  Model Number: ");
		fwrite(htip->modelNumber.info, htip->modelNumber.size, 1, out);
	}
	if (htip->macftlvs[0]) {
		fprintf(out, "\nBegin MAC forward TLVs\n");
	} else {
		goto PRINTEND;
	}
	for (int i = 0; i < MAXPORTS; i++) {
		if (!htip->macftlvs[i]) {
			fprintf(out, "\nEnd MAC forward TLVs");
			break;
		} else {
			MACFTLV_PTR macftlv = htip->macftlvs[i];
			fprintf(out, "iface type (length): %d\n", macftlv->ifLength);
			fprintf(out, "iface type: %d\n", macftlv->ifType);
			fprintf(out, "port number (length): %d\n", macftlv->portLength);
			fprintf(out, "port number: %d\n", macftlv->portNumber);
			fprintf(out, "number of mac addresses: %d\n", macftlv->macLength);
			int index = 0;
			while (index < macftlv->macLength) {
				fprintf(out, " mac: ");
				for (int i = 0; i < 6; i++) {
					fprintf(out, "%2x", macftlv->macs[index * 6 + i]);
					if (i != 5) {
						fprintf(out, ":");
					} else {
						fprintf(out, "\n");
					}
				}
				index++;
			}
		}
	}
	PRINTEND: fprintf(out, "\n------END------\n");
	if (htip->macs.info && htip->macs.acount != 0) {
		fprintf(out, "HTIP-ethernet bridge mac addresses: %d\n",
				htip->macs.acount);
		for (int index = 0; index < htip->macs.acount; index++) {
			fprintf(out, "  mac: ");
			for (int i = 0; i < 6; i++) {
				fprintf(out, "%2x", htip->macs.info[index * 6 + i]);
				if (i != 5) {
					fprintf(out, ":");
				} else {
					fprintf(out, "\n");
				}
			}
		}
	}
}

void freeHTIP(HTIPPAYLOAD_PTR htip) {
	if (htip->packet.data) {
		free(htip->packet.data);
	}
	for (int i = 0; i < MAXPORTS; i++) {
		if (!htip->macftlvs[i]) {
			break;
		} else {
			free(htip->macftlvs[i]);
		}
	}
	free(htip);
}

////////////////////////////////
// JSON related functions
////////////////////////////////

void putInfopiece(INFOPIECE_PTR buffer, INFOPIECE_PTR info, char * tag) {
	if (info->info) {
		buffer->size += sprintf((char *) buffer->info + buffer->size,
				"\"%s\":\"", tag);
		memcpy(buffer->info + buffer->size, info->info, info->size);
		buffer->size += info->size;
		if (buffer->info[buffer->size - 1] == 0) {
			buffer->size--;
		}
		buffer->size += sprintf((char *) buffer->info + buffer->size, "\",\n");
	}
}
void putMac(INFOPIECE_PTR buffer, uint8_t * mac) {
	for (int i = 0; i < 6; i++) {
		buffer->size += sprintf((char *) buffer->info + buffer->size, "%02x",
				mac[i]);
		if (i != 5) {
			buffer->info[buffer->size] = ':';
			buffer->size++;
		}
	}
}

void putMacTLVs(INFOPIECE_PTR buffer, MACFTLV_PTR mactable) {
	if (mactable) {
		buffer->size += sprintf((char *) buffer->info + buffer->size, "{\n");
		buffer->size += sprintf((char *) buffer->info + buffer->size,
				"\"interfaceType\":\"%d", mactable->ifType);
		buffer->size += sprintf((char *) buffer->info + buffer->size, "\",\n");
		buffer->size += sprintf((char *) buffer->info + buffer->size,
				"\"portNumber\":\"%d", mactable->portNumber);
		buffer->size += sprintf((char *) buffer->info + buffer->size, "\",\n");
		buffer->size += sprintf((char *) buffer->info + buffer->size,
				"\"macentries\":[\n");
		for (int i = 0; i < mactable->macLength; i++) {
			buffer->info[buffer->size++] = '"';
			putMac(buffer, &mactable->macs[i * 6]);
			buffer->info[buffer->size++] = '"';
			if (i != mactable->macLength - 1) {
				buffer->size += sprintf((char *) buffer->info + buffer->size,
						",\n");
			} else {
				buffer->size += sprintf((char *) buffer->info + buffer->size,
						"]\n");
			}
		}
		buffer->size += sprintf((char *) buffer->info + buffer->size, "},\n");
	}
}

int getMacAsString(char * dst, uint8_t * mac) {
	int index = 0;

	uint8_t res = 0;
	uint8_t rem = 0;
	for (int i = 0; i < 6; i++) {
		res = mac[i] / 16;
		rem = mac[i] % 16;
		if (res < 10) {
			dst[index++] = '0' + res;
		} else {
			dst[index++] = 'A' + res - 10;
		}
		if (rem < 10) {
			dst[index++] = '0' + rem;
		} else {
			dst[index++] = 'A' + rem - 10;
		}
		if (i != 5) {
			dst[index++] = ':';
		} else {
			dst[index++] = '\0';
		}
	}
	//don't count the final closing \0
	return index - 1;
}

char * AsJSON(HTIPPAYLOAD_PTR htip) {
	unsigned char * json = malloc(2048);
	INFOPIECE buffer;
	buffer.size = 0;
	buffer.info = json;
	if (!json) {
		return NULL;
	}
	buffer.size += sprintf((char *) buffer.info + buffer.size, "{\n");
	char macbuffer[20]; //it should be 17
	getMacAsString(macbuffer, htip->src.info);
	buffer.size += sprintf((char *) buffer.info + buffer.size,
			"\"src\":\"%s\",\n", macbuffer);
	putInfopiece(&buffer, &htip->chasisId, "chasisId");
	putInfopiece(&buffer, &htip->portId, "portId");
	if (htip->ttl.acount) {
		buffer.size += sprintf((char *) buffer.info + buffer.size,
				"\"ttl\":\"%d\",\n", htip->ttl.acount);
	}
	putInfopiece(&buffer, &htip->portDescription, "portDescription");
	putInfopiece(&buffer, &htip->deviceCategory, "deviceCategory");
	putInfopiece(&buffer, &htip->manufacturerCode, "manufacturerCode");
	putInfopiece(&buffer, &htip->modelName, "modelName");
	putInfopiece(&buffer, &htip->modelNumber, "modelNumber");
	if (htip->macftlvs[0]) {
		buffer.size += sprintf((char *) buffer.info + buffer.size,
				"\"forwardingTable\":[\n");
		for (int i = 0; i < MAXPORTS; i++) {
			putMacTLVs(&buffer, htip->macftlvs[i]);
		}
		//remove the last ",\n" from the buffer and replace it
		buffer.size -= 2;
		buffer.size += sprintf((char *) buffer.info + buffer.size, "]\n");
	}

	buffer.size += sprintf((char *) buffer.info + buffer.size, "}");
	return (char *) buffer.info;
}

