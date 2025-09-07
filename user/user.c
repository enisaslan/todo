#include "user.h"
#include "string.h"
#include "../cjson/cJSON.h"

user_t local_storage[4] = {
    [0].state = 1,
    [0].name = "Enis\0",
    [0].last_name = "Aslan\0",
    [0].password = "1234",
    [0].email = "enis",

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

int send_todo_list(session_t* s)
{
    int ret;
    todo_t *todo;
    int i = 0;
    int todo_count = get_todo_count(s->user);
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
    
    ret = send_ws_message(s->socket_id, json_str, strlen(json_str));
    if(ret > 0)
    {
        printf("Total %d Bytes WS data sended...\r\n", ret);
    }

    cJSON_Delete(root);
    free(json_str);

    return 0;
}
