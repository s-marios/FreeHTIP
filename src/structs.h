/**
 * \file
 * \brief Data structures such as network headers, packets and data information structures
 *
 * Declaration of various structures used throughout the code.
 */
#ifndef __PACKET_STRUCTS
#define __PACKET_STRUCTS

#include <stddef.h>
#include <stdint.h>

/**
 * Ethernet Header Structure
 */
typedef struct {
	uint8_t DST[6];
	uint8_t SRC[6];
	uint16_t ETHTYPE;
} ETHHEADER, *ETHHEADER_PTR;

/**
 * Frame control structure that keeps indexes associated with a PACKET structure.
 */
typedef struct {
	size_t allocated; /*!< allocated bytes for this packet */
	size_t used; /*!< .. i don't think this is used.. */
	size_t dataoffset; /*!<data offset. data will be written in this offset. Doubles as packet size indicator */
} PACKETCONTROL;

/**
 * The main data structure representing a datalink frame.
 */
typedef struct {
	PACKETCONTROL control; /*!< control structure for keeping track allocation and usage */
	uint8_t * data; /*!< actual pointer to the underlying buffer */
} PACKET, *PACKET_PTR;

/**
 * A TLV structure used during creation and parsing of TLV values
 */
typedef struct {
	union {
		PACKET_PTR packet;
		uint8_t * data;
	};
	uint8_t type;
	size_t size;
	size_t datastart;
} TLV, *TLV_PTR;

/**
 * A generic structure for keeping information about a parsed TLV
 */
typedef struct {
	size_t size; /*!< if the info field is used, it indicates the length of it */
	uint32_t acount; /*!< Used to keep simple numerical values (mostly TTL though). Various usages. */
	uint8_t * info; /*!< pointer to a buffer that keeps the actual data */
} INFOPIECE, *INFOPIECE_PTR;

/**
 * Special structure that keeps the Mac Forwarding Table TLV
 */
typedef struct {
	uint8_t ifLength; /*!< length of the interface type */
	uint32_t ifType; /*!< type of the interface */
	uint8_t portLength; /*!< port length */
	uint32_t portNumber; /*!< port number */
	uint8_t macLength; /*!< Number of mac entries, NOT LENGTH OF THE macs field */
	uint8_t * macs; /*!<raw data that will be used for as mac addresses. for each 6 bytes macLength should increase by 1 */
} MACFTLV, *MACFTLV_PTR;

/** maximum number of ports in a mac forwarding table */
#define MAXPORTS 64
/**
 * The core structure that holds data of a parsed LLDP/HTIP frame. See details for each field.
 */
typedef struct {
	uint8_t datalinkType; /*!< to support various datalink layers. also the pointer in sfptrs*/
	uint32_t recvTime; /*!< relative time this frame was received, in SECONDS */
	PACKET packet; /*!< original frame that was parsed */
	INFOPIECE src; /*!< mac address from which this HTIP frame originated */
	INFOPIECE parseResult; /*!< parse result */
	INFOPIECE chasisId; /*!< LLDP chasis id (type 1) */
	INFOPIECE portId; /*!< LLDP port id (type 2) */
	INFOPIECE ttl; /*!< LLDP Time To Live (type 3) */
	INFOPIECE portDescription; /*!< LLDP port description (type 4) */
	INFOPIECE deviceCategory; /*!< HTIP device category (type 127, htip sub/dev.inf: 1/1) */
	INFOPIECE manufacturerCode; /*!< HTIP manufacturerCode (type 127, htip sub/dev.inf: 1/2) */
	INFOPIECE modelName; /*!< HTIP model name (type 127, htip sub/dev.inf: 1/3) */
	INFOPIECE modelNumber; /*!< HTIP model number (type 127, htip sub/dev.inf: 1/4 */
	INFOPIECE macs; /*!< Mac addresses for this HTIP agent (type 127, htip sub/dev.inf: 3/1 */
	INFOPIECE extMacs; /*!< Extended Mac addresses  (type 127, htip sub/dev.inf: 5/1 */
	MACFTLV_PTR macftlvs[MAXPORTS]; /*!< Mac forwarding table (type 127, htip sub/dev.inf: 2/1 */
} HTIPPAYLOAD, *HTIPPAYLOAD_PTR;

#endif
