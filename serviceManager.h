#ifndef __SERVICE_MANAGER_H__
#define __SERVICE_MANAGER_H__

#include "stdint.h"
#include "unistd.h"

#define MAX_NUMBER_OF_SERVICE   32

/** session service function type definitin */
typedef int (*session_service_fn_t)(void*);

int 
set_service(session_service_fn_t service, 
            uint8_t id);

session_service_fn_t
get_service(uint8_t id);

void 
service_map_clear(void);

#endif /* __SERVICE_MANAGER_H__ */
