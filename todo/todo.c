#include "todo.h"
#include "string.h"


int create_new_todo(void* user, char* summary, char* details)
{
    todo_t* todo;
    int i;
    int todo_count = get_todo_count(user);
    int summary_length = strlen(summary);
    int details_length = strlen(details);

    if(summary_length > MAX_TODO_SUMMARY_LENGTH)
    {
        return -2;
    }


    if(details_length > MAX_TODO_DETAIL_LENGTH)
    {
        return -3;
    }

    if(todo_count < MAX_TODO_COUNT)
    {
        for(i = 0; i < MAX_TODO_COUNT; i++)
        {
            todo = &user->todo_list[i];
            if(todo->state == TODO_FREE)
            {
                todo->state = TODO_ACTIVE;
                strncpy(todo->summary, summary, MAX_TODO_SUMMARY_LENGTH);
                strncpy(todo->details, details, MAX_TODO_DETAIL_LENGTH);
                return 0;
            }
        }
    }

    return -1;
}


int get_todo_count(void* user)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &user->todo_list[i];
        if(todo->state != TODO_FREE)
        {
            count++;
        }
    }

    return count;
}

int get_completed_todo_count(void* user)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &user->todo_list[i];
        if(todo->state == TODO_COMPLETED)
        {
            count++;
        }
    }

    return count;
}


int get_active_todo_count(void* user)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &user->todo_list[i];
        if(todo->state == TODO_ACTIVE)
        {
            count++;
        }
    }

    return count;
}


void create_mock_todo(void* user)
{
    create_new_todo(user, "Source Parsing\0", "C Source code should split to other related source files.\0");
    create_new_todo(user, "Madal Form Creation\0", "JS Modal Creation Techniques is researches\0");

}
