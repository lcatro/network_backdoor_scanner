
#ifndef _LOCAL_THREAD_H__
#define _LOCAL_THREAD_H__

unsigned long create_thread(void* function_address,void* function_parameter_list);
void          wait_thread(unsigned long thread_handle);
void          close_thread(unsigned long thread_handle);

#endif

