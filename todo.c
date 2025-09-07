#include "todo.h"
#include "string.h"

int 
get_todo_count(todo_t *todo_list)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &todo_list[i];
        if(todo->state != TODO_FREE)
        {
            count++;
        }
    }

    return count;
}

int 
get_completed_todo_count(todo_t *todo_list)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &todo_list[i];
        if(todo->state == TODO_COMPLETED)
        {
            count++;
        }
    }

    return count;
}


int 
get_active_todo_count(todo_t *todo_list)
{
    int i; 
    int count = 0;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &todo_list[i];
        if(todo->state == TODO_ACTIVE)
        {
            count++;
        }
    }

    return count;
}

int 
create_new_todo(todo_t *todo_list, 
                char* summary, 
                char* details)
{
    todo_t* todo;
    int i;
    int todo_count = get_todo_count(todo_list);
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
            todo = &todo_list[i];
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


void 
create_mock_todo(todo_t *todo_list)
{
    create_new_todo(todo_list, "C Source Code Parsing\0", "Split the C source code to other related source files.\0");
    create_new_todo(todo_list, "Modal Form Create\0", "Research the modal creation techniques with the JS.\0");
}
