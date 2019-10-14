/**
 * \file
 * \brief L2 agent header, exposing some default
 * htip fields.
 *
 * You can customize the fields below to your liking.
 */

#ifndef L2AGENT_H_
#define L2AGENT_H_

#include "stdint.h"

/* mostly store static information */
extern char * portDescription;
extern char * deviceCategory;
extern char * manufacturerCode;
extern char * modelName;
extern char * modelNumber;
extern char * status;
extern uint8_t channelUseState;
extern uint8_t signalStrength;
extern uint8_t communicationError;
extern uint8_t sendInterval;
extern uint8_t ttl;

#endif /* L2AGENT_H_ */
