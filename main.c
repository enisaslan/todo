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

#include "todo.h"
#include "ws.h"
#include "serviceManager.h"

/** session service function type definitin */
// typedef int (*session_service_fn_t)(void*);

// session_service_fn_t service_map[32];


#define SERVER_PORT     8081
#define RX_BUFFER_SIZE  4096

typedef enum connection_stage_t
{
    CONN_STAGE_HTTP = 0,
    CONN_STAGE_WS = 1,
    CONN_STAGE_LOGOUT = 2,
    CONN_STAGE_LOGIN = 3
}connection_stage_t;

typedef struct user_t
{
    uint8_t state;
    char name[32];
    char last_name[32];
    char password[32];
    char email[32];
    todo_t todo_list[MAX_TODO_COUNT];
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

int data_exchange(void *session);

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


/**
 * @brief session type definition 
 */ 
typedef struct session_t
{
    int id;
    int socket_id; 
    char* buffer;
    int data_len;
    user_t *user;
    session_service_fn_t service;

    int stage;
    int precondition;

}session_t;

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
        ws_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)login_data);

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
                create_mock_todo(user->todo_list);

                printf("User Name: %s %s - Mail: %s\r\n", user->name, user->last_name, user->email);
                
                user->state = 2;

                int active_todo_cnt = get_active_todo_count(user->todo_list);
                int completed_todo_cnt = get_completed_todo_count(user->todo_list);
                cJSON *ok_root = cJSON_CreateObject();

                // Alan ekle
                cJSON_AddStringToObject(ok_root, "state", "login_ok");
                cJSON_AddStringToObject(ok_root, "name", user->name);
                cJSON_AddStringToObject(ok_root, "last_name", user->last_name);
                cJSON_AddNumberToObject(ok_root, "active_count", active_todo_cnt);
                cJSON_AddNumberToObject(ok_root, "completed_count", completed_todo_cnt);

                char *json_str = cJSON_PrintUnformatted(ok_root);
                
                ret = ws_send_message(s->socket_id, json_str, strlen(json_str));
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

int send_todo_list(session_t* s)
{
    int ret;
    todo_t *todo;
    int i = 0;
    int todo_count = get_todo_count(s->user->todo_list);
    cJSON *root = cJSON_CreateObject();
    cJSON *todo_list = cJSON_AddArrayToObject(root, "todo_list");

    // Alan ekle
    cJSON_AddStringToObject(root, "type", "data");
    cJSON_AddNumberToObject(root, "response", 101);
    cJSON_AddNumberToObject(root, "todo_count", todo_count);

    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &s->user->todo_list[i];

        if(todo->state != TODO_FREE)
        {
            cJSON_AddItemToArray(todo_list, cJSON_CreateNumber(todo->state));
            cJSON_AddItemToArray(todo_list, cJSON_CreateString(todo->summary));
            cJSON_AddItemToArray(todo_list, cJSON_CreateString(todo->details));
        }
    }

    char *json_str = cJSON_PrintUnformatted(root);
    
    ret = ws_send_message(s->socket_id, json_str, strlen(json_str));
    if(ret > 0)
    {
        printf("Total %d Bytes WS data sended...\r\n", ret);
    }

    cJSON_Delete(root);
    free(json_str);

    return 0;
}

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

    char x_data[4096];
    if(s->data_len < 4096)
    {
        memset(x_data, 0, 4096);
        ws_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)x_data);
        root = cJSON_Parse(x_data);
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
            else 
            {
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
        ws_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)lpc_ack);

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
    ret = ws_send_message(s->socket_id, msg, msg_len);
    if(ret > 0)
    {
        printf("Total %d Bytes WS data sended...\r\n", ret);
    }

    s->service = session_create_login_page_ack;

    return 0;
}

int stage_logout(void* session)
{
    session_t* s = (session_t*)(session);

    if(CONN_STAGE_LOGOUT != s->stage)
    {
        return -1;
    }

    session_validate_login(session);

    return 0;
}

int stage_connection(void* session)
{
    session_t* s = (session_t*)(session);
    char* key_addr;

    printf("Stage: WS Connection State ... \r\n");

    if(CONN_STAGE_WS != s->stage)
    {
        return -1;
    }

    /** Find the "Sec-WebSocket-Key" */ 
    key_addr = strstr(s->buffer, "Sec-WebSocket-Key: ");
    if(NULL != key_addr)
    {
        /** Send Connection OK ACK */
        ws_send_connection_ok(s->socket_id, s->buffer);
        s->precondition = 0xEA; 
        return 0;
    }
    else if(0xEA == s->precondition)
    {
        const char* ws_ack = {"{\"ws\":\"ack\"}\0"};
        uint8_t ack_data[20];
        int i;
        int ret;
        
        if(s->data_len < 20)
        {
            memset(ack_data, 0, 20);
            ws_decode_frame((uint8_t*)s->buffer, s->data_len, (uint8_t*)&ack_data);

            printf("State 3E4E - Data Len %d - Data %s\r\n", s->data_len, ack_data);

            ret = strcmp((const char *)ack_data, ws_ack);
            if(0 == ret)
            {
                printf("State 3E5A\r\n");
                s->precondition = 0;
                s->stage = CONN_STAGE_LOGOUT;

                //s->service = session_create_login_page;
                //s->service(s);
                return 0;
            }
        }
    }
    
    return -1;
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
    session->service = stage_connection;

    session->stage = CONN_STAGE_WS; /** !!! HTTP */

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

            //if(CONN_STAGE_WS == session->stage)
            //{
                session_service_fn_t service = get_service(session->stage);
                if(NULL != service)
                {
                    service(session);
                }
            //}
            //else if (CONN_STAGE_LOGOUT == session->stage) 
            //{
            //    session_service_fn_t service = get_service(CONN_STAGE_WS);
            //}
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
    service_map_clear();

    (void)set_service(stage_connection, CONN_STAGE_WS);
    (void)set_service(stage_logout, CONN_STAGE_LOGOUT);
    
   
    server_start();
    return 0;
}


