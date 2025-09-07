#ifndef __USER_USER_H__
#define __USER_USER_H__
#include "stdint.h"
#include "unistd.h"
#include "../todo/todo.h"

typedef struct user_t
{
    uint8_t state;
    char name[32];
    char last_name[32];
    char password[32];
    char email[32];
    todo_t todo_list[MAX_TODO_COUNT];
}user_t;


#endif