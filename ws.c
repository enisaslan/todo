#include "ws.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "sys/socket.h"

void 
ws_decode_frame(uint8_t *frame, 
                        size_t frame_len, 
                        uint8_t* ret_frame) 
{
    if (frame_len < 6) 
    {
        printf("Frame Length invalid !!\r\n");
        return;
    }

    uint8_t fin_opcode = frame[0];
    uint8_t fin  = (fin_opcode >> 7) & 0x01;
    uint8_t opcode = fin_opcode & 0x0F;
    uint8_t mask_payload_len = frame[1];
    uint8_t mask = (mask_payload_len >> 7) & 0x01;
    uint64_t payload_len = mask_payload_len & 0x7F;
    size_t offset = 2;

    // Extended payload length (126 veya 127 ise)
    if (payload_len == 126) 
    {
        payload_len = (frame[offset] << 8) | frame[offset + 1];
        offset += 2;
    } 
    else if (payload_len == 127) 
    {
        // 64-bit length (burada örnekte yok ama koyalım)
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | frame[offset + i];
        }
        offset += 8;
    }

    uint8_t mask_key[4] = {0};
    if(mask) 
    {
        for (int i = 0; i < 4; i++) 
        {
            mask_key[i] = frame[offset + i];
        }

        offset += 4;
    }

    if(frame_len < offset + payload_len) 
    {
        printf("- Missing byte in Frame !\n");
        return;
    }


    for(uint64_t i = 0; i < payload_len; i++) 
    {
        if (mask)
            ret_frame[i] = frame[offset + i] ^ mask_key[i % 4];
        else
            ret_frame[i] = frame[offset + i];
    }

    ret_frame[payload_len] = '\0'; // null-terminate
}



int 
ws_send_message(int socketID, 
                const char* data, 
                uint16_t data_len)
{
    int ret;
    if(data_len < 126)
    {
        unsigned char ws_frame[1024];
        ws_frame[0] = 0x81;  /** FIN=1, text frame */
        ws_frame[1] = (uint8_t)data_len;
        memcpy(&ws_frame[2], data, data_len);
        return send(socketID, ws_frame, data_len + 2, 0);
    }
    else  /// 126Byte - 65535Byte 
    {
        unsigned char* ws_frame = malloc(65535);
        if(NULL == ws_frame)
        {
            printf("WS Send Buffer Allocation Fail\r\n");
            return -1;
        }
        
        // clear the ws buffer
        memset(ws_frame, 0, 65535);

        ws_frame[0] = 0x81;  /** FIN=1, text frame */
        ws_frame[1] = 126; /** No Mask(Bit 7) + Use the Extended Data Length Area */
        ws_frame[2] = (uint8_t)(data_len >> 8); // extended length area 
        ws_frame[3] = (uint8_t)(data_len); // extended data length area
        memcpy(&ws_frame[4], data, data_len);

        ret = send(socketID, ws_frame, data_len + 4, 0);

        free(ws_frame);

        return ret;
    }

    return -1;
}

