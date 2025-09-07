#ifndef __SESSION_SESSION_H__
#define __SESSION_SESSION_H__

/** session service function type definitin */
typedef int (*session_service_fn_t)(void*);

/**
 * @brief session type definition 
 */ 
typedef struct session_t
{
    int id;
    int socket_id; 
    char *buffer;
    int data_len;
    void *user;
    session_service_fn_t service;
}session_t;

int session_idle(void* session);
void session_delete(session_t* session);
int session_create_login_page(void* session);
int session_connection(void* session); 
int session_validate_login(void* session);
#endif
