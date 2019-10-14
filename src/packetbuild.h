/**
 * \file
 * \brief Main definitions for frame creation, parsing and data structures is here, make sure to read this
 * \author Sioutis Marios
 *
 * This file contains the function declarations for almost all of the project. Consider breaking this up appropriately.
 * Most of these functions are implemented in the demo.c file, which should also be split up to smaller chunks.
 * Due to lack of time I suggest splitting out the packet creation stuff from the main processing stuff.
 *
 * Anything that is not documented should be treated as implementation detail, and probably should not be used directly.
 */
#ifndef __PACKETBUILD_H
#define __PACKETBUILD_H

#include "structs.h"
/**
 * Initializes a PACKET_PTR with a buffer of 1500 bytes.
 * @return a pointer to the PACKET structure that was initialized.
 */
PACKET_PTR allocatePacket(void);
//PACKET_PTR growPacket(PACKET_PTR packet);
/**
 * Frees a packet that was created with allocatePacket()
 * @param packet The packet whose memory should be freed.
 */
void freePacket(PACKET_PTR packet);

/**
 * Appends a single byte character to the frame
 * @param packet the frame that the character will be appended to
 * @param achar the byte to add
 * @return a pointer to the frame
 */
PACKET_PTR pPoke(PACKET_PTR packet, uint8_t achar);

/**
 * Appends a multi-byte sequence of characters to the frame
 * @param packet the frame to which the data will be appended
 * @param data pointer to the multi-byte sequencce
 * @param length the length of the multi-byte sequence
 * @return a pointer to the frame
 */
PACKET_PTR pPokeMany(PACKET_PTR packet, const uint8_t * data, size_t length);

/**
 * Initialize a TLV
 * @param packet the frame that this tlv will be appended to
 * @param type the type of this tlv
 * @return a TLV structure pointer
 */
TLV_PTR initTLV(PACKET_PTR packet, uint8_t type);

/**
 * Appends a single character to the tlv
 * @param tlv the TLV the character will be appended to
 * @param achar the byte to append
 * @return a pointer to the TLV
 */
TLV_PTR tlvPoke(TLV_PTR tlv, uint8_t achar);
/**
 * Appends a multi-byte sequence to the tlv
 * @param tlv the TLV to append to
 * @param data pointer to the multi-byte sequence
 * @param length the length of the multi-byte sequence
 * @return a pointer to the TLV
 */
TLV_PTR tlvPokeMany(TLV_PTR tlv, const uint8_t * data, size_t length);

/**
 * Performs finalization of the given TLV. Must be called for each call to initTLV(), after data has been appended
 * @param tlv the TLV to finalize
 * @return the finalized TLV
 */
TLV_PTR finalizeTLV(TLV_PTR tlv);

/**
 * Frees up the memory taken by the TLV
 * @param tlv The TLV to free
 */
void freeTLV(TLV_PTR tlv);
uint16_t getTLVLength(TLV_PTR tlv);
unsigned char getTLVType(TLV_PTR tlv);

uint16_t parseTLVLength(uint8_t * data);
uint8_t parseTLVType(uint8_t * data);

/**
 * Appends the special last TLV (which is an empty, terminator-style TLV of zeroes)
 * @param packet the frame to which to add the last tlv
 */
void createLastTLV(PACKET_PTR packet);
/**
 * Appends the LLDP type 1 chasis tlv to the frame
 * @param packet the frame to add this tlv
 * @param type type of the chassis as specified by the LLDP protocol
 * @param data buffer that holds the chassis id data
 * @param length the buffer length
 */
void createChasisIDTLV(PACKET_PTR packet, uint8_t type, uint8_t * data,
		size_t length);
/**
 * Appends the LLDP type 2 port id tlv to the frame
 * @param packet the frame to add this tlv
 * @param type the type of port
 * @param data buffer that holds the port id data
 * @param length the buffer length
 */
void createPortIDTLV(PACKET_PTR packet, uint8_t type, uint8_t * data,
		size_t length);
/**
 * Appends the LLDP type 3 Time To Live tlv to the frame
 * @param packet the frame to add this tlv
 * @param ttl the Time To Live value.
 */
void createTTLTLV(PACKET_PTR packet, uint16_t ttl);
/**
 * Appends the LLDP type 4 port description tlv to the frame
 * @param packet the frame to add this tlv
 * @param data buffer that holds the port description data
 * @param length the buffer length
 */
void createPortDescriptionTLV(PACKET_PTR packet, uint8_t * data, size_t length);

/**
 * OUI (Organization Unique Identifier) for the TTC group
 */
static const uint8_t TTC_OUI[] = { 0xE0, 0x27, 0x1A };
/**
 * Appends the device category tlv (HTIP sub/dev.inf:1/1) to the frame
 * @param packet the frame to add this tlv
 * @param deviveCategory the buffer that holds the device category data
 * @param length length of the buffer
 */
void createDeviceCategoryTLV(PACKET_PTR packet, uint8_t * deviveCategory,
		size_t length);
/**
 * Appends the manufacturer code tlv (HTIP sub/dev.inf:1/2) to the frame
 * @param packet the frame to add this tlv
 * @param manufacturerCode a 6-byte buffer that represent the manufacturer code (longer buffers will be truncated)
 */
void createManufacturerCodeTLV(PACKET_PTR packet, uint8_t * manufacturerCode);
/**
 * Appends the model name tlv (HTIP sub/dev.inf: 1/3) to the frame
 * @param packet the frame to add this tlv
 * @param modelName buffer with the model name
 * @param length length of the buffer
 */
void createModelNameTLV(PACKET_PTR packet, uint8_t * modelName, size_t length);
/**
 * Appends the model number tlv (HTIP sub/dev.inf: 1/4) to the frame
 * @param packet the frame to add this tlv
 * @param modelNumber buffer with the model number
 * @param length length of the buffer
 */
void createModelNumberTLV(PACKET_PTR packet, uint8_t * modelNumber,
		size_t length);

/**
 * Appends the HTIP subtype 1.20 channel usage information tlv to the frame
 *
 * @param packet the frame to add this tlv
 * @param channelUsage the channel usage (range: 0-100)
 */
void createChannelUseStateTLV(PACKET_PTR packet, uint8_t channelUsage);

/**
 * Appends the HTIP subtype 1.21 signal strength information tlv to the frame
 * @param packet the frame to add this tlv to
 * @param signalStrength the signal strength (range:0-100)
 */
void createSignalStrengthTLV(PACKET_PTR packet, uint8_t signalStrength);

/**
 * Appends the HTIP subtype 1.22 communication error information tlv to the frame
 * @param packet the frame to add this tlv to
 * @param error the communication error (range:0-100)
 */
void createCommunicationErrorTLV(PACKET_PTR packet, uint8_t error);

/**
 * Appends the HTIP subtype 1.50 status information tlv to the frame
 *
 * @param packet the frame to add this tlv to
 * @param size the length of the data for this status information
 * @param data the status information
 */
void createStatusInformationTLV(PACKET_PTR packet, uint8_t size,
		const uint8_t * data);

/**
 * Appends the HTIP subtype 1.80 lldpdu send interval information tlv to the frame
 * @param packet the frame to add this tlv to
 * @param interval the update interval, in seconds
 */
void createLLDPDUSendInterval(PACKET_PTR packet, uint16_t interval);

/**
 * Appends a vendor-specific extension HTIP tlv. Optional support,
 * not taken into consideration by the HTIP Manager
 * @param packet the frame to add this tlv
 * @param orgCode organization code (6 bytes)
 * @param deviceInfoType device information type
 * @param deviceInfo buffer that holds the device information used in this extension
 * @param length size of deviceInfo buffer
 */
void createDeviceInfoEXTTLV(PACKET_PTR packet, uint8_t * orgCode,
		uint8_t deviceInfoType, uint8_t * deviceInfo, uint8_t length);
/**
 * Appends the Mac Table forwarding tlv to the frame
 * @param packet the frame to add this tlv
 * @param macf the mac forwarding table as a MACFTLV pointer
 */
void createMacForwardingTLVstruct(PACKET_PTR packet, MACFTLV_PTR macf);

/** start a TLV that holds the MAC addresses for extended connectivity information.
 * \sa addExtendedMac endExtendedTlv
 */
TLV_PTR startExtendMacTlv(PACKET_PTR packet, uint8_t numberOfMacs);

/** add a mac of variable size to the tlv that holds mac addresses
 * @param tlv a tlv initiated with startExtendMacTlv
 * @param length the length of the mac address
 * @param mac the mac address itself
 * */
void addExtendedMac(TLV_PTR tlv, uint8_t length, uint8_t * mac);

/**
 * finalizes an extended tlv.
 *
 * It is used in conjunction with startExtendedMacTlv and startExtendedConnectivityInformation
 *
 * @param tlv a tlv initiated with startExtendedMacTlv
 */
void endExtendedTlv(TLV_PTR tlv);

/** starts a tlv that contains extended connectivity information (HTIP extension) */
TLV_PTR startExtendConnnectivityInformation(PACKET_PTR packet);

/** adds port length, port number, mac length, mac number and total number
 * of per host information occurences in an extended tlv
 *
 * @param tlv the extended tlv
 * @param portLength the length of a port entry, in bytes
 * @param portNum total port numbers
 * @param macLength the length of the mac address
 * @param macNum the total number of mac addresses
 * @param perHostInfoNum the total number of per host information occurences
 */
void addExtendedPortAndMacInfo(TLV_PTR tlv, uint8_t portLength,
		uint32_t portNum, uint8_t macLength, uint8_t macNum,
		uint8_t perHostInfoNum);

/**
 * add per host information to the extended tlv previously initialized.
 * @param tlv the extended tlv
 * @param macLength the length of the mac address
 * @param mac the mac address
 * @param signalStrength the signal strength for this host (range: 0-100)
 * @param errorPercentage the error percentage for this host (range: 0-100)
 *
 */
void addPerHostInfo(TLV_PTR tlv, uint8_t macLength, uint8_t * mac,
		int8_t signalStrength, int8_t errorPercentage);

/**
 * add the number of paired mac addresses in an extendet tlv
 *
 * @param tlv the extended tlv
 * @param infoNumbers number of paired mac addresses
 */
void addPerPortInfoNumber(TLV_PTR tlv, uint8_t infoNumbers);

/** add the paired mac addresses in an extended tlv
 * @param tlv the extended tlv
 * @param macNums the number of paired addresses
 * @param macs a pointer to an array where the mac addresses are kept (as character arrays)
 */
void addPerPortPairedMacs(TLV_PTR tlv, uint8_t macNums, uint8_t macLength,
		uint8_t ** macs);

/**
 * add channel utilization information to an extended tlv. After this function is called,
 * don't forget to finalize the extended tlv
 *
 * @param tlv the extended tlv
 * @param channelNum the number of channels associated with this port
 * @param channelInfo an array of bytes that stores channel usage information
 *
 * \sa endExtendedTlv
 */
void addPerPortChannelInfo(TLV_PTR tlv, uint8_t channelNum,
		uint8_t * channelInfo);

#endif
