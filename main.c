#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define SERVER_PORT     8081
#define RX_BUFFER_SIZE  4096
#define CLIENT_KEY_SIZE 256

typedef enum session_state_t
{
    SESSION_STATE_CONNECT = 10, 
    SESSION_STATE_WS,
    SESSION_STATE_LOGIN,
    SESSION_STATE_HOME,
    SESSION_STATE_IDLE
}session_state_t;

typedef struct session_t
{
    int id;
    int socket_id; 
    session_state_t state;
}session_t;

/**
 * @brief Session creation service.
 */
session_t* 
create_session(int socketID)
{   
    static int id = 0;
    session_t* session; 
    session = malloc(sizeof(session_t));
    
    if(session)
    {
        session->id = id;
        session->socket_id = socketID;
        session->state = SESSION_STATE_CONNECT;
        id++;
    }
    
    return session;
}

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

void* clientThread(void *arg)
{
    int ret;
    int socketID = *((int *)arg);
    char* client_key = malloc(CLIENT_KEY_SIZE);
    char* buffer = malloc(RX_BUFFER_SIZE);
    char* key_addr;
    int ret_size;

    if(NULL == buffer)
    {
        printf(" - Memory Allocation ERROR for Socket %d \r\n", socketID);
        return NULL;
    }

    /** Create a connection session */
    session_t* session = create_session(socketID);
    if(NULL == session)
    {
        printf(" - Session Creation Error !!!\r\n");
        return NULL;
    }

    /** Set session state as web-socket auth */
    session->state = SESSION_STATE_WS;

    printf("Running Session ID %d - Socket ID %d \r\n", session->id, session->socket_id);

    while(1)
    {
        /** sleep thread */
        usleep(1000);
        
        /** Clear the memory */
        memset(buffer, 0, RX_BUFFER_SIZE);

        /** Read the available data */
        ret_size = read(session->socket_id, buffer, RX_BUFFER_SIZE);
        if(ret_size > 0)
        {
            if(session->state == SESSION_STATE_WS)
            {
                /** Find the "Sec-WebSocket-Key" */ 
                key_addr = strstr(buffer, "Sec-WebSocket-Key: ");
                if(NULL != key_addr)
                {
                    memset(client_key, 0, CLIENT_KEY_SIZE);

                    key_addr += strlen("Sec-WebSocket-Key: ");
                    sscanf(key_addr, "%s", client_key);

                    printf("Client %d - Key: %s \r\n", session->socket_id, client_key);

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

                    ret = send(session->socket_id, response, strlen(response), 0);
                    if(ret > 0)
                    {
                        printf("Total %d Bytes Handshake data sended...\r\n", ret);
                    }

                    session->state = SESSION_STATE_IDLE;
                }
                else 
                {
                    printf("Other Data: %s\r\n", buffer);
                }
            }
            else if(session->state == SESSION_STATE_LOGIN)
            {
                /** Send login page create command */
                const char *msg = "{\r\n\"state\":\"login\"\r\n}";
                int msg_len = strlen(msg);
                ret = send_ws_message(session->socket_id, msg, msg_len);
                if(ret > 0)
                {
                    printf("Total %d Bytes WS data sended...\r\n", ret);
                }
            }
            else if(session->state == SESSION_STATE_HOME)
            {
                
            }
            else if(session->state == SESSION_STATE_IDLE)
            {
             
            }

        }
        else if (ret_size == 0) 
        {
            printf(" Client %d Dead !!!\r\n", session->socket_id);
            close(session->socket_id);

            free(session);

            return NULL;
        }

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


