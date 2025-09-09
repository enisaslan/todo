#include "serviceManager.h"
#include <stdint.h>
#include "stdio.h"

session_service_fn_t service_map[MAX_NUMBER_OF_SERVICE];

session_service_fn_t
get_service(uint8_t id)
{
    if(id < MAX_NUMBER_OF_SERVICE)
    {
        return service_map[id];
    }

    return NULL;
}   

int 
set_service(session_service_fn_t service, 
            uint8_t id)
{
    if(id < MAX_NUMBER_OF_SERVICE)
    {
        service_map[id] = service;

        return 0;
    }

    return -1;
}


void 
service_map_clear(void)
{
    int i;
    
    for(i = 0; i < MAX_NUMBER_OF_SERVICE; i++)
    {
        service_map[i] = NULL;
    }
}
