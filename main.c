#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "cjson/cJSON.h"

#define SERVER_PORT     8081
#define RX_BUFFER_SIZE  4096
#define CLIENT_KEY_SIZE 256

typedef enum todo_state_t
{
    TODO_FREE = 0,
    TODO_ACTIVE,
    TODO_COMPLETED
}toto_state_t;

typedef struct todo_t
{
    char summary[32];
    char detailed_info[512];
    toto_state_t state;
}todo_t;

typedef struct user_t
{
    uint8_t state;
    char name[32];
    char last_name[32];
    char password[32];
    char email[32];
    todo_t todo_list[64];
}user_t;

user_t local_storage[4] = {
    [0].state = 1,
    [0].name = "Enis\0",
    [0].last_name = "Aslan\0",
    [0].password = "ee12aa34",
    [0].email = "enis.aslan",

    [1].state = 1,
    [1].name = "Sare\0",
    [1].last_name = "Aslan\0",
    [1].password = "ss12aa34",
    [1].email = "sare.aslan",

    [2].state = 1,
    [2].name = "Beyza\0",
    [2].last_name = "Aslan\0",
    [2].password = "bb12aa34",
    [2].email = "beyza.aslan",

    [3].state = 0,

};

user_t* 
find_user(char* email, char* pass)
{
    int state;
    user_t* iter;
    int i;
    for(i = 0; i < 4; i++)
    {
        iter = &local_storage[i];

        if(0 == iter->state)
        {
            continue;
        }
        
        state = strcmp(iter->email, email);
        if(0 == state)
        {
            state = strcmp(iter->password, pass);
            if(0 == state)
            {
                return iter;
            }
        }
    }

    return NULL;
}


/** session service function type definitin */
typedef int (*session_service_fn_t)(void*);


/**
 * @brief session type definition 
 */ 
typedef struct session_t
{
    int id;
    int socket_id; 
    char* buffer;
    int data_len;
    session_service_fn_t service;
}session_t;

int 
send_ws_message(int socketID, 
                const char* data, 
                int data_len)
{
    unsigned char ws_frame[512];

    ws_frame[0] = 0x81;  /** FIN=1, text frame */
    ws_frame[1] = data_len;
    memcpy(&ws_frame[2], data, data_len);

    return send(socketID, ws_frame, data_len + 2, 0);
}


void 
websocket_decode_frame(uint8_t *frame, 
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
    if (payload_len == 126) {
        payload_len = (frame[offset] << 8) | frame[offset + 1];
        offset += 2;
    } else if (payload_len == 127) {
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
session_validate_login(void* session)
{
    session_t* s = (session_t*)(session);
    cJSON *root;
    cJSON *email;
    cJSON *pass;
    user_t* user = NULL;
    int ret;

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
            printf("User Name: %s %s - Mail: %s\r\n", user->name, user->last_name, user->email);
            user->state = 2;

            cJSON *ok_root = cJSON_CreateObject();

            // Alan ekle
            cJSON_AddStringToObject(ok_root, "state", "login_ok");
            cJSON_AddStringToObject(ok_root, "name", user->name);
            cJSON_AddStringToObject(ok_root, "last_name", user->last_name);
            
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

    return 0;
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



int ws_connection(void* session)
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


int session_idle(void* session)
{
    session_t* s = (session_t*)(session);

    printf("Session in IDLE State ... \r\n");

    return 0;
}

void 
session_delete(session_t* session)
{
    close(session->socket_id);
    free(session->buffer);
    free(session);
}

/**
 * @brief Session creation service.
 */
session_t* 
create_session(int socketID)
{   
    static int id = 0;
    session_t* session; 
    session = malloc(sizeof(session_t));
    
    if(NULL != session)
    {
        session->id = id;
        session->socket_id = socketID;
        session->service = session_idle;
        id++;

        session->buffer = malloc(RX_BUFFER_SIZE);
        if(NULL == session->buffer)
        {
            printf(" - Buffer Memory Allocation ERROR for Socket %d \r\n", socketID);
            free(session);
            return NULL;
        }

        memset(session->buffer, 0, RX_BUFFER_SIZE);
    }
    
    return session;
}


void* 
clientThread(void *arg)
{
    int ret;
    int socketID = *((int *)arg);
    
    int ret_size;

    /** Create a connection session */
    session_t* session = create_session(socketID);
    if(NULL == session)
    {
        printf(" - Session Creation Error !!!\r\n");
        return NULL;
    }

    /** Set session state as web-socket auth */
    session->service = ws_connection;

    printf("Running Session ID %d - Socket ID %d \r\n", session->id, session->socket_id);

    while(1)
    {

        /** Clear the memory */
        memset(session->buffer, 0, RX_BUFFER_SIZE);

        /** Read the available data */
        ret_size = read(session->socket_id, session->buffer, RX_BUFFER_SIZE);
        if(ret_size > 0)
        {
            session->data_len = ret_size;
            session->service(session);
        }
        else if (ret_size == 0) 
        {
            printf(" Client %d Dead !!!\r\n", session->socket_id);
            session_delete(session);
            return NULL;
        }


        /** sleep thread */
        //usleep(500000);
        usleep(1000);
    }
}


int 
server_start(void)
{
    int ret;
    struct timeval tv;
    int serverSocket;
    int newSocket;
    int opt = 1;
    int i=0;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    pthread_t threadIDList[10];

    /* create main socket */ 
    serverSocket = socket(PF_INET, SOCK_STREAM, 0);
    ret = setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if(ret < 0)
    {
        printf(" - Socket option setting ERROR !!\r\n");
        return -1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY; // inet_addr("127.0.0.1");

    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

    ret = bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if(ret < 0)
    {
        printf(" - Server Socket Binding ERROR !!\r\n");
        return -2;
    }

    /* listen the connection port */
    if(0 == listen(serverSocket,100))
    {
        printf(" > Server Started on Port %d\r\n", SERVER_PORT);

        while(1)
        {
            addr_size = sizeof(serverStorage);
            newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size);

            tv.tv_sec = 0;
            tv.tv_usec = 200;
            setsockopt(newSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

            ret = pthread_create(&threadIDList[i++], NULL, clientThread, &newSocket); 
            if(0 == ret)
            {
                printf("Client Connected (Thread Created)...\r\n");
            }
            else 
            {
                printf("Client Thread Create ERROR !!!\r\n");
            }
        }
    }
    else
    {
        printf(" - Server Start ERROR !!!\r\n");
    }
    

    return ret;
}

int 
main(void)
{
    server_start();
    return 0;
}


