
#pragma warning (disable:4786)

#include <math.h>

#include <windows.h>

#include "encoder_base64.h"
#include "resolver_express.h"
#include "resolver_string.h"


typedef vector<string> arg_list;


string resolve_express_http(const string express) {
    string result;
    split_result split(split_string(express,find_string(express,";")));

    if (split.second.empty())
        return split.first;

    string format_string(split.first);
    left_move_string(split.second,1);
    string arg_string(split.second);
    split=split_string(split.second,find_string(split.second,","));
    arg_list list;

    while (!split.second.empty()) {
        list.push_back(split.first);
        left_move_string(split.second,1);
        split=split_string(split.second,find_string(split.second,","));
    }
    list.push_back(split.first);

    string element;
    string element_name,element_value;
    unsigned int arg_index=0;
    split=split_string(format_string,find_string(format_string,","));

    while (!split.second.empty()) {
        element=split.first;
        split_result element_split(split_string(element,find_string(element,":")));
        left_move_string(element_split.second,1);
        element_name=element_split.first;
        element_value=element_split.second;

        if (-1!=find_string(element_value,"%")) {
            left_move_string(element_value,find_string(element_value,"%")+1);//  TIPS : There is no Get Type ..
            //  But I dont want to use it ..
            element_value=list[arg_index];
            ++arg_index;
        }
        result+=element_name;
        result+=":";
        result+=element_value;
        result+="\r\n";
        left_move_string(split.second,1);
        split=split_string(split.second,find_string(split.second,","));
    }
    split_result element_split(split_string(split.first,find_string(split.first,":")));
    left_move_string(element_split.second,1);
    element_name=element_split.first;
    element_value=element_split.second;

    if (-1!=find_string(element_value,"%")) {
        left_move_string(element_value,find_string(element_value,"%")+1);//  TIPS : There is no Get Type ..
        //  But I dont want to use it ..
        element_value=list[arg_index];
        ++arg_index;
    }
    result+=element_name;
    result+=":";
    result+=element_value;
    result+="\r\n\r\n";

    return result;
}

static long ramdon(long down,long up) {
    srand(GetTickCount());
    return down+(rand()*(up-down)/32768);
}

/*

    function(123123)|function(321312)
    function(function(313213123))

    function:rnd arg:[down-up]
        rnd([1-100])

*/

static const string function_rnd("rnd");
static const string function_time("time");
static const string function_len("len");
static const string function_base64("base64");

static bool resolve_express_is_function_name(const string function_name) {
    if (!function_name.empty())
        if (-1==find_string(function_name,"(") &&
            -1==find_string(function_name,")") &&
            -1==find_string(function_name,"-") &&
            -1==find_string(function_name,"|") &&
            -1==string_to_number(function_name))
            return true;
    return false;
}

static bool resolve_express_is_function(const string express) {
    split_result split(split_string(express,"("));
    string function_name(split.first),function_arg(separate_string(express,"(",")"));

    if (resolve_express_is_function_name(function_name) && !function_arg.empty())
        return true;
    return false;
}

string resolve_express_function(const string express) {
    if (!resolve_express_is_function(express)) return "";

    split_result split(split_string(express,"|"));
    string function(split.first),next_function(split.second);
    left_move_string(next_function,1);
    string result;

    while (!function.empty()) {
        if (!resolve_express_is_function(function)) return function;

        split=split_string(function,"(");
        string function_name(upper_string(split.first)),function_arg(separate_string(function,"(",")"));

        if (function_rnd==function_name) {
            function_arg=separate_string(function_arg,"[","]");
            string down,up;
            split=split_string(function_arg,"-");
            if (1<count_string(function_arg,"-")) {
                left_move_string(split.second,1);
                if (resolve_express_is_function(split.second)) {
                    down=split.first;
                    up=split.second;
                    left_move_string(up,1);
                } else {
                    split=split_string(function_arg,")");
                    down=split.first;
                    down+=")";
                    left_move_string(split.second,1);
                    split=split_string(split.second,"-");
                    left_move_string(split.second,1);
                    up=split.second;
                }
            } else {
                down=split.first;
                up=split.second;
                left_move_string(up,1);
            }

            if (down.empty() || up.empty())
                return "";

            if (resolve_express_is_function(down))
                down=resolve_express_function(down);
            if (resolve_express_is_function(up))
                up=resolve_express_function(up);

            long down_=string_to_number(down),up_=string_to_number(up);
            long rnd=ramdon(down_,up_);
            result+=number_to_string(rnd);
        } else if (function_time==function_name) {
        } else if (function_base64==function_name) {
            if (!resolve_express_is_function(function_arg)) {
                return base64_encode(function_arg.c_str(),function_arg.length());
            } else {
                string encode_string(resolve_express_function(function_arg));
                return base64_encode(encode_string.c_str(),encode_string.length());
            }
        } else if (function_len==function_name) {
            unsigned int length=function_arg.length();
            return number_to_string(length);
        }
        split=split_string(next_function,",");
        function=split.first;
        next_function=split.second;
        left_move_string(next_function,1);
    }
    return result;
}

static string resolve_express_resolve_function(const string express,const string function_name) {
    string result;
    split_result split;
    string function;
    split=split_string(express,function_name);
    result+=split.first;
    function=split.second;
    split=split_string(function,")");
    function=split.first;
    function+=")";
    left_move_string(split.second,1);
    result+=resolve_express_function(function);
    result+=split.second;
    return result;
}

string resolve_express(const string express) {
    string result(express);

    while (1) {
        if (-1!=find_string(result,"rnd(")) {
            result=resolve_express_resolve_function(result,"rnd(");
        } else if (-1!=find_string(result,"base64(")) {
            result=resolve_express_resolve_function(result,"base64(");
        } else if (-1!=find_string(result,"time()")) {
            //function="time()";
        } else if (-1!=find_string(result,"len(")) {
            result=resolve_express_resolve_function(result,"len(");
        } else
            break;
    }
    return result;
}
