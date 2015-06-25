

#ifndef _RESOVLVER_DICTIONARY_H__
#define _RESOVLVER_DICTIONARY_H__


#ifndef _STRING_

#include <string>

using std::string;
using std::pair;

#endif

#ifndef _MAP_

#include <map>

using std::map;

#endif

#ifndef _VECTOR_

#include <vector>

using std::vector;

#endif


typedef vector<string> username_list;
typedef vector<string> password_list;
typedef map<string,password_list> dictionary;


dictionary resolve_dictionary_open(const string dictionary_path);
dictionary resolve_dictionary_open(const string username_path,const string password_path);

bool resolve_dictionary_is_empty(const dictionary& in_dictionary);
unsigned int resolve_dictionary_get_user_count(const dictionary& in_dictionary);
username_list resolve_dictionary_get_user_list(const dictionary& in_dictionary);
unsigned int resolve_dictionary_get_password_count(const dictionary& in_dictionary);
password_list resolve_dictionary_get_password_list(const dictionary& in_dictionary,const string username);

#endif
