


#include <windows.h>

#include "local_thread.h"

unsigned long create_thread(void* function_address,void* function_parameter_list) {
    HANDLE thread_handle=CreateThread(NULL,NULL,(LPTHREAD_START_ROUTINE)function_address,(LPVOID)function_parameter_list,NULL,NULL);
    if (INVALID_HANDLE_VALUE!=thread_handle)
        return (unsigned long)thread_handle;
    return -1;
}

void wait_thread(unsigned long thread_handle) {
    WaitForSingleObject((HANDLE)thread_handle,INFINITE);
}

void close_thread(unsigned long thread_handle) {
    CloseHandle(thread_handle);
}
