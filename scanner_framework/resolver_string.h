
#ifndef _RESOLVER_STRING_H__
#define _RESOLVER_STRING_H__

#ifndef _STRING_

#include <string>

using std::string;

#endif

#ifndef _PAIR_
#define _PAIR_

using std::pair;

#endif

#ifndef _VECTOR_

#include <vector>

using std::vector;

#endif

typedef vector<string> split_block_result;
typedef pair<string,string> split_result;


unsigned int find_string       (const string in_string,const string find_string);
unsigned int find_last_string  (const string in_string,const string find_string);
split_result split_string      (const string in_string,unsigned int split_point);
split_result split_string      (const string in_string,const string split_string);
split_block_result split_block (const string in_string,const string split_string);
void         erase_string      (string& in_string,unsigned int erase_point,unsigned int erase_length);
unsigned int count_string      (string in_string,const string find_string);
void         left_move_string  (string& in_string,unsigned int move_offset);
void         right_move_string (string& in_string,unsigned int move_offset);
void         left_remove_space (string& in_string);
void         right_remove_space(string& in_string);
void         left_remove       (string& in_string,const string remove_string);
void         right_remove      (string& in_string,const string remove_string);
string       separate_string   (const string in_string,const string left_string,const string right_string);
string       separate_string   (const string in_string,const unsigned int split_offset,const unsigned int separete_length);
void         replace_string    (string& in_string,const string source_string,const string dest_string);

string       upper_string(const string in_string);

string       number_to_string(long in_number);
long         string_to_number(const char* input_string);
long         string_to_number(const string& input_string);

#endif
