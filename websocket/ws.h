#ifndef __WEBSOCKET_WS_H__
#define __WEBSOCKET_WS_H__
#include "stdint.h"
#include "unistd.h"

#define CLIENT_KEY_SIZE 256

void websocket_decode_frame(uint8_t *frame, 
                            size_t frame_len, 
                            uint8_t* ret_frame);

int 
send_ws_message(int socketID, 
                const char* data, 
                uint16_t data_len);

#endif
