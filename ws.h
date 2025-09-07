#ifndef __WS_WS_H__
#define __WS_WS_H__

#include "stdint.h"
#include "unistd.h"

void 
ws_decode_frame(uint8_t *frame, 
                        size_t frame_len, 
                        uint8_t* ret_frame);

int 
ws_send_message(int socketID, 
                const char* data, 
                uint16_t data_len);

#endif