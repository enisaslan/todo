#include "todo.h"
#include "string.h"
#include "stdio.h"

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
                todo->id = i;
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
    int todo_count = get_todo_count(todo_list);
    if(0 == todo_count)
    {
        create_new_todo(todo_list, "Code Refactor\0", "C and JS source will be refactor.\0");
        create_new_todo(todo_list, "New Todo Form Create\0", "New todo form create that likes a modal form.\0");
        create_new_todo(todo_list, "Edit Form Create\0", "Edit todo form create that likes a modal form\0");
        create_new_todo(todo_list, "Create New User\0", "New User Form Create\0");
        create_new_todo(todo_list, "Password Reset System\0", "Password Reset System & Form Create\0");
    }
}


int delete_todo_by_id(todo_t *todo_list, int id)
{
    int i;
    todo_t* todo;
    for(i = 0; i < MAX_TODO_COUNT; i++)
    {
        todo = &todo_list[i];
        if((todo->state != TODO_FREE) && (todo->id == id))
        {
            todo->state = TODO_FREE; 
            printf(" > Todo %d deleted \r\n", i);
            return 0;
        }
    }

    return -1;
}