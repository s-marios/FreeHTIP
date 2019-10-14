/**
 * \file
 * \brief packet parsing and printing related functions declared here
 *
 * Main header declaration of packet parsing and printing functions here
 */
#ifndef __PACKET_PARSE_H
#define __PACKET_PARSE_H

#include <stdio.h>
#include "structs.h"

/**
 * Checks if two packets are from the same source
 */
int isFromSameSourceEther(HTIPPAYLOAD_PTR htipnew, HTIPPAYLOAD_PTR htipold);
/**
 * Copies data to the internal storage of the htip structure. Must be called after allocating htip.
 * all the INFOPIECE entries of this htip will be pointing to the newly copied data
 * @param htip htip payload structure to be initialized with the data
 * @param size size of the data
 * @param data the original data that will be copied
 */
void setHTIPdata(HTIPPAYLOAD_PTR htip, size_t size, uint8_t * data);
/**
 * Parses a raw data buffer into an HTIPPAYLOAD structure.
 * @param htip a pointer to the HTIPPAYLOAD structure which the data will be parsed into
 * @param data WARNING, READ THIS CAREFULLY: points to the exact start of the LLDP frame BUT: if the
 * htip structure has already used the function setHTIPData(), this argument will be ignored!
 * @param length the length of the lldp frame (will also be ignored if setHTIPData() was used)
 * @return the htip payload pointer with the information fields populated
 */
HTIPPAYLOAD_PTR parseLLDP(HTIPPAYLOAD_PTR htip, uint8_t * data, size_t length);
/**
 * Prints the HTIPPAYLOAD structure to the stream out, in a human readable form
 * @param htip the payload to print
 * @param out the stream to print to
 */
void printHTIP(HTIPPAYLOAD_PTR htip, FILE * out);
/**
 * Frees an HTIPPAYLOAD structure and all its fields, including the copied data from the original frame
 * @param htip a pointer to the structure whose memory will be freed
 */
void freeHTIP(HTIPPAYLOAD_PTR htip);
/**
 * Allocates a character buffer that contains the HTIPPAYLOAD information in JSON format (don't forget to free the buffer
 * afterwards)
 * @param htip the structure that will be represented as JSON
 * @return a character buffer with the JSON data
 */
char * AsJSON(HTIPPAYLOAD_PTR htip);

/**
 * definition for functions that check if two packets are from the same source
 */
typedef int (*SAMESOURCEFPTR)(HTIPPAYLOAD_PTR, HTIPPAYLOAD_PTR);
/**
 * array of "same source" functions. The index is associated with a protocol.
 * Right now only index 0 is defined and this is for normal ethernet/lldp packets.
 * When GRE extension with IPv6 is implemented, a "same source" function for IPv6 must be
 * added to this table
 */
SAMESOURCEFPTR sfptrs[] = { &isFromSameSourceEther };

/**
 * Internal use
 */
extern TLV_PTR parseFromData(uint8_t * data);

/**
 * Free a tlv.
 */
extern void freeTLV(TLV_PTR tlv);

#endif
