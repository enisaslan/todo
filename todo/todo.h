#ifndef __TODO_TODO_H__
#define __TODO_TODO_H__
#include "stdint.h"
#include "unistd.h"

#define MAX_TODO_COUNT  64
#define MAX_TODO_SUMMARY_LENGTH  32
#define MAX_TODO_DETAIL_LENGTH  512

typedef enum todo_state_t
{
    TODO_FREE = 0,
    TODO_ACTIVE,
    TODO_COMPLETED
}toto_state_t;

typedef struct todo_t
{
    char summary[MAX_TODO_SUMMARY_LENGTH];
    char details[MAX_TODO_DETAIL_LENGTH];
    toto_state_t state;
}todo_t;

int create_new_todo(void* user, char* summary, char* details);
int get_todo_count(void* user);
int get_completed_todo_count(void* user);
int get_active_todo_count(void* user);

#endif
