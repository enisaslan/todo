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
#include "session/session.h"

#define SERVER_PORT     8081
#define RX_BUFFER_SIZE  4096



int execute_request(session_t* s, int req_id)
{
    if(req_id == 101) // get todo list
    {
        send_todo_list(s);        
    }

    return 0;
}

int data_exchange(void *session)
{
    session_t* s = (session_t*)(session);
    cJSON *root;
    cJSON *type;
    cJSON *req;
    int itype = 3;
    int state;
    user_t *user = NULL;
    int ret;

    printf("exchange data received 1 \n");

    char login_data[4096];
    if(s->data_len < 4096)
    {
        memset(login_data, 0, 4096);
        websocket_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)login_data);

        printf("exchange data received 2. \n");

        root = cJSON_Parse(login_data);
        if (root == NULL) 
        {
            printf("JSON parse ERROR!\n");
            return 1;
        }

        type = cJSON_GetObjectItemCaseSensitive(root, "type");
        if(NULL == type)
        {
            itype = 0;
        }

        if(cJSON_IsString(type) && type->valuestring != NULL && itype != 0) 
        {
            state = strcmp(type->valuestring, "data\0");
            if(0 == state)
            {
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
                    itype = 0;
                }
            }
        }
        else 
        {
            printf("Unknown Data Type\r\n");
            itype = 0;
        }

        if(itype == 1) // data
        {
            printf("Data received \r\n");
            req = cJSON_GetObjectItemCaseSensitive(root, "request");
            if(NULL != type)
            {
                if(cJSON_IsNumber(req))
                {
                    execute_request(s, req->valueint);
                }
            }
            else {
                itype = 0;
            }
        }
        else if(itype == 2) // ack 
        {
            printf("ACK data received \r\n");
        }

        cJSON_Delete(root);
    }
    else 
    {
        printf("Invalid Data Size %d \r\n", s->data_len);
    }


    return 0;
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
    session->service = session_connection;

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
            printf(" Rx \n");
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


