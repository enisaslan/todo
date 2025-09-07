#include "ws.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "sys/socket.h"
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

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

void ws_send_connection_ok(int socket_id, 
                            const char* data)
{
    char* key_addr;
    int ret;

    printf("Session in WS Connection State ... \r\n");

    /** Find the "Sec-WebSocket-Key" */ 
    key_addr = strstr(data, "Sec-WebSocket-Key: ");

    char client_key[CLIENT_KEY_SIZE];
    memset(client_key, 0, CLIENT_KEY_SIZE);

    key_addr += strlen("Sec-WebSocket-Key: ");
    sscanf(key_addr, "%s", client_key);

    printf("Client %d - Key: %s \r\n", socket_id, client_key);

    /** This GUID defined in RFC6455 ve RFC4122 documents */
    char to_hash[256];
    snprintf(to_hash, sizeof(to_hash), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);

    /** Calculate SHA1 */
    unsigned char sha1_result[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)to_hash, strlen(to_hash), sha1_result);
    
    unsigned char encoded_data[CLIENT_KEY_SIZE];
    memset(encoded_data, 0, CLIENT_KEY_SIZE);

    /** Base64 encode */
    EVP_EncodeBlock((unsigned char*)&encoded_data, (const unsigned char*)&sha1_result, SHA_DIGEST_LENGTH);

    printf("Base64 Encoded Data: %s \r\n", encoded_data);

    /** Handshake */
    char response[2*CLIENT_KEY_SIZE];
    memset(response, 0, 2*CLIENT_KEY_SIZE);

    snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n",
            encoded_data);

    ret = send(socket_id, response, strlen(response), 0);
    if(ret > 0)
    {
        printf("Total %d Bytes Handshake data sended...\r\n", ret);
    }
}