
#pragma warning (disable:4503)
#pragma warning (disable:4786)

#include <malloc.h>
#include <memory.h>
#include <stdio.h>

#include "resolver_dictionary.h"
#include "resolver_string.h"


dictionary resolve_dictionary_open(const string dictionary_path) {
    dictionary result;
    FILE* file_handle=fopen(dictionary_path.c_str(),"r");
    
    if (NULL!=file_handle) {
        fseek(file_handle,0,SEEK_END);
        unsigned long file_length=ftell(file_handle);

        if (!file_length) {
            char* file_buffer=(char*)malloc(file_length);

            if (NULL!=file_buffer) {
                fseek(file_handle,0,SEEK_SET);
                memset(file_buffer,0,file_length);
                fread(file_buffer,1,file_length,file_handle);
                string resolve_string(file_buffer);

                try {
                    unsigned long resolve_point=find_string(resolve_string,"\r\n");
                    split_result split;
                    while (!resolve_point) {
                        split=split_string(resolve_string,resolve_point);
                        string line(split.first);
                        split_result split_line(split_string(line,find_string(line," ")));
                        left_move_string(split_line.second,1);
                        string username(split_line.first),password(split_line.second);
                        left_remove_space(username);
                        right_remove_space(username);
                        left_remove_space(password);
                        right_remove_space(password);
                        result[username].push_back(password);
                        resolve_string=split.second;
                        left_move_string(resolve_string,2);
                        resolve_point=find_string(resolve_string,"\r\n");
                    }
                } catch (...) {
                }
                free(file_buffer);
            }
        }
        fclose(file_handle);
    }
    return result;
}

dictionary resolve_dictionary_open(const string username_path,const string password_path) {
    dictionary result;
    password_list password_list_;
    FILE* file_username=fopen(username_path.c_str(),"r");
    FILE* file_password=fopen(password_path.c_str(),"r");
    
    if (NULL!=file_username && NULL!=file_password) {
        fseek(file_username,0,SEEK_END);
        fseek(file_password,0,SEEK_END);
        unsigned long file_username_length=ftell(file_username);
        unsigned long file_password_length=ftell(file_password);

        if (!file_username_length && !file_password_length) {
            char* file_username_buffer=(char*)malloc(file_username_length);
            char* file_password_buffer=(char*)malloc(file_password_length);

            if (NULL!=file_username_buffer && NULL!=file_password_buffer) {
                fseek(file_username,0,SEEK_SET);
                memset(file_username_buffer,0,file_username_length);
                fread(file_username_buffer,1,file_username_length,file_username);
                fseek(file_password,0,SEEK_SET);
                memset(file_password_buffer,0,file_password_length);
                fread(file_password_buffer,1,file_password_length,file_username);

                string resolve_username(file_username_buffer);
                string resolve_password(file_password_buffer);

                try {
                    unsigned long resolve_point=find_string(resolve_password,"\r\n");
                    split_result split;

                    while (!resolve_point) {
                        split=split_string(resolve_password,resolve_point);
                        left_remove_space(split.first);
                        right_remove_space(split.first);
                        password_list_.push_back(split.first);
                        resolve_password=split.second;
                        left_move_string(resolve_password,2);
                        resolve_point=find_string(resolve_password,"\r\n");
                    }
                } catch(...) {
                }

                try {
                    unsigned long resolve_point=find_string(resolve_password,"\r\n");
                    split_result split;
                    while (!resolve_point) {
                        split=split_string(resolve_username,resolve_point);
                        result.insert(pair<string,password_list>(split.first,password_list_));
                        resolve_username=split.second;
                        left_move_string(resolve_username,2);
                        resolve_point=find_string(resolve_username,"\r\n");
                    }
                } catch(...) {
                }
                free(file_username_buffer);
                free(file_password_buffer);
            }
        }
        fclose(file_username);
        fclose(file_password);
    }
    return result;
}

bool resolve_dictionary_is_empty(const dictionary& in_dictionary) {
    return in_dictionary.empty();
}

unsigned int resolve_dictionary_get_user_count(const dictionary& in_dictionary) {
    return in_dictionary.size();
}

username_list resolve_dictionary_get_user_list(const dictionary& in_dictionary) {
    username_list result;

    for (dictionary::const_iterator iterator=in_dictionary.begin();
         iterator!=in_dictionary.end();
         ++iterator)
        result.push_back(iterator->first);

    return result;
}

unsigned int resolve_dictionary_get_password_count(const dictionary& in_dictionary) {
    if (!resolve_dictionary_is_empty(in_dictionary))
        return in_dictionary.begin()->second.size();
    return 0;
}

password_list resolve_dictionary_get_password_list(const dictionary& in_dictionary,const string username) {
    password_list result;
    for (dictionary::const_iterator iterator=in_dictionary.begin();
         iterator!=in_dictionary.end();
         ++iterator) {
        if (username==iterator->first) {
            result=iterator->second;
            break;
        }
    }

    return result;
}
