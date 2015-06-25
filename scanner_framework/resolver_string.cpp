
#pragma warning (disable:4786)

#include <math.h>

#include "resolver_string.h"


unsigned int find_string(const string in_string,const string find_string) {
    return (unsigned int)in_string.find(find_string);
}

unsigned int find_last_string(const string in_string,const string find_string) {
    return (unsigned int)in_string.find_last_of(find_string);
}

split_result split_string(const string in_string,unsigned int split_point) {
    split_result result;

    if (split_point<=in_string.length()) {
        result.first=in_string.substr(0,split_point);
        result.second=in_string.substr(split_point,in_string.length());
    } else
        result.first=in_string;
    return result;
}

split_result split_string(const string in_string,const string split_string_) {
    return split_string(in_string,find_string(in_string,split_string_));
}

split_block_result split_block(const string in_string,const string split_string_) {
    split_block_result result;

    if (!in_string.empty()) {
        split_result block;
        block.second=in_string;

        while (-1!=find_string(block.second,split_string_)) {
            block=split_string(block.second,split_string_);
            left_move_string(block.second,1);

            if (!block.first.empty())
                result.push_back(block.first);
        }
        result.push_back(block.second);
    }

    return result;
}

void erase_string(string& in_string,unsigned int erase_point,unsigned int erase_length) {
    if (in_string.empty()) return;
    if (!(in_string.length()>=erase_point+erase_length)) return;

    string output_string(in_string.substr(0,erase_point));
    output_string+=in_string.substr(erase_point+erase_length,in_string.length());
    in_string=output_string;
}

unsigned int count_string(string in_string,const string find_string_) {
    unsigned int next_point=find_string(in_string,find_string_),count=0;
    while (-1!=next_point) {
        in_string=in_string.substr(next_point+1,in_string.length());
        ++count;next_point=find_string(in_string,find_string_);
    }
    return count;
}

void left_move_string(string& in_string,unsigned int move_offset) {
    if (in_string.empty()) return;
    in_string=in_string.substr(move_offset,in_string.length());
}

void right_move_string(string& in_string,unsigned int move_offset) {
    if (in_string.empty()) return;
    in_string=in_string.substr(move_offset,in_string.length()-move_offset);
}

void left_remove(string& in_string,const string remove_string) {
    if (in_string.empty()) return;
    unsigned int find_index=0;

    while (!(find_index=in_string.find(remove_string)))
        in_string=in_string.substr(1,in_string.length());
}
void right_remove(string& in_string,const string remove_string) {
    if (in_string.empty()) return;
    unsigned int find_index=0;

    while (in_string.length()==(find_index=in_string.find_last_of(remove_string)+1))
        in_string=in_string.substr(0,in_string.length()-1);
}

void left_remove_space(string& in_string) {
    left_remove(in_string," ");
}

void right_remove_space(string& in_string) {
    right_remove(in_string," ");
}

string separate_string(const string in_string,const string left_string,const string right_string) {
    if (-1==find_string(in_string,left_string) || -1==find_string(in_string,right_string))
        return "";

    split_result split(split_string(in_string,find_string(in_string,left_string)+1));
    return split_string(split.second,find_last_string(split.second,right_string)).first;
}


string separate_string(const string in_string,const unsigned int split_offset,const unsigned int separete_length) {
    split_result split(split_string(in_string,split_offset));

    return split_string(split.second,separete_length).first;
}

string upper_string(const string in_string) {
    string result;

    for (string::const_iterator iterator=in_string.begin();
         iterator!=in_string.end();
         ++iterator) {
        char char_=*iterator;
        if ('A'<=char_ && char_<='Z')
            char_+=32;
        result+=char_;
    }
    return result;
}

string number_to_string(long in_number) {
    string result;
    char link_string[16]={0};
    sprintf(link_string,"%ld",in_number);
    result=link_string;
    return result;
}

long string_to_number(const char* input_string) {
    long return_number=0;
    try {
        for (int number_index=strlen(input_string)-1;number_index>=0;--number_index,++input_string) {
            if (48<=*input_string && *input_string<=57)
                return_number+=(*input_string-48)*pow(10,number_index);
            else
                return -1;
        }
    } catch (...) {
        return -1;
    }
    return return_number;
}

long string_to_number(const string& input_string) {
    return string_to_number(input_string.c_str());
}
