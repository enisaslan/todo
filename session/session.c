#include "session.h"
#include "stdio.h"
#include <stdlib.h>
#include "string.h"
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "../websocket/ws.h"
#include "../cjson/cJSON.h"
#include "sys/socket.h"

int session_idle(void* session)
{
    session_t* s = (session_t*)(session);

    printf("Session in IDLE State ... \r\n");

    return 0;
}

void session_delete(session_t* session)
{
    close(session->socket_id);
    free(session->buffer);
    free(session);
}

int session_create_login_page_ack(void* session)
{
    session_t* s = (session_t*)(session);
    const char* w_ack = {"{\"lpc\":\"ack\"}\0"};
    char lpc_ack[20];
    int ret;

    printf("Session in LOGIN Page ACK Wait State ... Data Len %d \r\n", s->data_len);

    if(s->data_len < 20)
    {
        memset(lpc_ack, 0, 20);
        websocket_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)lpc_ack);

        printf("LPC ACK data: %s \r\n", lpc_ack);

        ret = strcmp((const char *)lpc_ack, w_ack);
        if(0 == ret)
        {
            printf(" LPC ACK OK => %s \r\n", lpc_ack);
            s->service = session_validate_login;
        }
    }

    return 0;
}

int 
session_create_login_page(void* session)
{
    session_t* s = (session_t*)(session);
    int ret;

    printf("Session in Create Login page ... \r\n");

    /** Send login page create command */
    const char *msg = "{\r\n\"state\":\"login\"\r\n}";
    int msg_len = strlen(msg);
    ret = send_ws_message(s->socket_id, msg, msg_len);
    if(ret > 0)
    {
        printf("Total %d Bytes WS data sended...\r\n", ret);
    }

    s->service = session_create_login_page_ack;

    return 0;
}


int session_connection(void* session)
{
    session_t* s = (session_t*)(session);
    char* key_addr;
    int ret;

    printf("Session in WS Connection State ... \r\n");

    /** Find the "Sec-WebSocket-Key" */ 
    key_addr = strstr(s->buffer, "Sec-WebSocket-Key: ");
    if(NULL != key_addr)
    {
        char client_key[CLIENT_KEY_SIZE];
        memset(client_key, 0, CLIENT_KEY_SIZE);

        key_addr += strlen("Sec-WebSocket-Key: ");
        sscanf(key_addr, "%s", client_key);

        printf("Client %d - Key: %s \r\n", s->socket_id, client_key);

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

        ret = send(s->socket_id, response, strlen(response), 0);
        if(ret > 0)
        {
            printf("Total %d Bytes Handshake data sended...\r\n", ret);
        }
    }
    else 
    {
        const char* ws_ack = {"{\"ws\":\"ack\"}\0"};
        uint8_t ack_data[20];
        int i;
        int ret;
        printf("Received an Other Data in WS Connection State. Data Len %d\r\n", s->data_len);
        
        if(s->data_len < 20)
        {
            memset(ack_data, 0, 20);
            websocket_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)&ack_data);

            printf("Received Data: %s \r\n", ack_data);
            ret = strcmp((const char *)ack_data, ws_ack);
            if(0 == ret)
            {
                printf(" ACK OK => %s \r\n", ack_data);
                s->service = session_create_login_page;
                s->service(s);
            }
        }
    }
    
    return 0;
}


int 
session_validate_login(void* session)
{
    session_t* s = (session_t*)(session);
    cJSON *root;
    cJSON *email;
    cJSON *pass;
    cJSON *type;
    int itype;
    int state;
    user_t *user = NULL;
    int ret;

    printf("session_validate_login !\n");

    char login_data[128];
    if(s->data_len < 128)
    {
        memset(login_data, 0, 128);
        websocket_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)login_data);

        root = cJSON_Parse(login_data);
        if (root == NULL) 
        {
            printf("JSON parse ERROR!\n");
            return 1;
        }

        type = cJSON_GetObjectItemCaseSensitive(root, "type");
        if(NULL == type)
        {
            return -1;
        }

        if(cJSON_IsString(type) && type->valuestring != NULL) 
        {
            state = strcmp(type->valuestring, "data\0");
            if(state == 0)
            {
                printf("Login Data Received\r\n");
                itype = 1;
            }
            else
            {
                state = strcmp(type->valuestring, "ack\0");
                if(0 == state)
                {
                    itype = 2;
                }
                else 
                {
                    printf("Unknown Data Type\r\n");
                    return -1;
                }
            }
        }
        else 
        {
            printf("Unknown Data Type\r\n");
            return -1;
        }

        if(1 == itype) // login data 
        {
            email = cJSON_GetObjectItemCaseSensitive(root, "email");
            pass = cJSON_GetObjectItemCaseSensitive(root, "password");

            if (cJSON_IsString(email) && email->valuestring != NULL) 
            {
                if (cJSON_IsString(pass) && pass->valuestring != NULL) 
                {
                    user = find_user(email->valuestring, pass->valuestring);
                }
            }

            if(NULL != user)
            {
                // update the session with the user;
                s->user = user;
             
                // test data create
                create_mock_todo(user);

                printf("User Name: %s %s - Mail: %s\r\n", user->name, user->last_name, user->email);
                
                user->state = 2;

                int active_todo_cnt = get_active_todo_count(user);
                int completed_todo_cnt = get_completed_todo_count(user);
                cJSON *ok_root = cJSON_CreateObject();

                // Alan ekle
                cJSON_AddStringToObject(ok_root, "state", "login_ok");
                cJSON_AddStringToObject(ok_root, "name", user->name);
                cJSON_AddStringToObject(ok_root, "last_name", user->last_name);
                cJSON_AddNumberToObject(ok_root, "active_count", active_todo_cnt);
                cJSON_AddNumberToObject(ok_root, "completed_count", completed_todo_cnt);

                char *json_str = cJSON_PrintUnformatted(ok_root);
                
                ret = send_ws_message(s->socket_id, json_str, strlen(json_str));
                if(ret > 0)
                {
                    printf("Total %d Bytes WS data sended...\r\n", ret);
                }

                cJSON_Delete(ok_root);
                free(json_str);
            }
            else 
            {
                printf("Please Check the your login info !!!\r\n");
            }
        }
        else if(2 == itype) 
        {
            printf("Ack Received -> Service changed to data_exchange \r\n");
            s->service = data_exchange;
        }

        cJSON_Delete(root);
    }

    return 0;
}

