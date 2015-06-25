
#pragma warning (disable:4786)

#include "resolver_html.h"
#include "resolver_string.h"


#define HTML_TAG_NAME "HTML_TAG_NAME"
#define HTML_TAG_SUBTAG "HTML_TAG_SUBTAG"


bool resolve_html_is_empty(const tag& in_tag) {
    if (in_tag.first.empty())
        return true;
    return false;
}

string resolve_html_get_tag_name(const tag& in_tag) {
    tag_data::const_iterator find_iterator=in_tag.first.find(HTML_TAG_NAME);

    if (find_iterator!=in_tag.first.end())
        return find_iterator->second;
    return "";
}

void resolve_html_set_tag_name(tag& in_tag,const string tag_name) {
    in_tag.first[HTML_TAG_NAME]=tag_name;
}

string resolve_html_get_tag_subtag(const tag& in_tag) {
    tag_data::const_iterator find_iterator=in_tag.first.find(HTML_TAG_SUBTAG);

    if (find_iterator!=in_tag.first.end())
        return find_iterator->second;
    return "";
}

void resolve_html_set_tag_subtag(tag& in_tag,const string tag_subtag) {
    in_tag.first[HTML_TAG_SUBTAG]=tag_subtag;
}

unsigned int resolve_html_get_tag_element_count(const tag& in_tag) {
    return in_tag.second.size();
}

tag_element_list resolve_html_get_tag_element_list(const tag& in_tag) {
    tag_element_list list;

    for (tag_element::const_iterator iterator=in_tag.second.begin();
         iterator!=in_tag.second.end();
         ++iterator)
        list.push_back(iterator->first);
    return list;
}

string resolve_html_get_tag_element(const tag& in_tag,const string element_name) {
    tag_element::const_iterator find_iterator=in_tag.second.find(element_name);

    if (find_iterator!=in_tag.second.end())
        return find_iterator->second;
    return "";
}

void resolve_html_set_tag_element(tag& in_tag,const string element_name,const string element_value) {
    in_tag.second[element_name]=element_value;
}

void resolve_html_delete_tag_element(tag& in_tag,const string element_name) {
    tag_element::const_iterator find_iterator=in_tag.second.find(element_name);

    if (find_iterator!=in_tag.second.end())
        in_tag.second.erase(element_name);
}

tag resolve_html_to_tag(const string in_string) {
    tag result;
    string resolve_string(in_string);
    unsigned int left_flag_front=find_string(in_string,"<");
    unsigned int right_flag_front=find_string(in_string,">");

    if (-1!=left_flag_front && -1!=right_flag_front) {
        unsigned int left_flag_back=in_string.find_last_of("</"),right_flag_back=in_string.find_last_of(">");

        if (-1!=left_flag_back && -1!=right_flag_back) {
            string first_tag,last_tag;
            split_result split(split_string(in_string,right_flag_front));
            first_tag=split.first;
            left_move_string(first_tag,left_flag_front+1);
            split=split_string(in_string,left_flag_back+1);
            last_tag=split.second;
            split=split_string(last_tag,last_tag.find_last_of(">"));
            last_tag=split.first;
            if (-1!=find_string(first_tag," ")) {
                split=split_string(first_tag,find_string(first_tag," "));
                first_tag=split.first;
            }

            if (first_tag==last_tag) {
                resolve_html_set_tag_name(result,first_tag);

                string resolve_string(separate_string(in_string,left_flag_front+1,right_flag_front-1));
                left_move_string(resolve_string,first_tag.length());
                left_remove_space(resolve_string);
                right_remove_space(resolve_string);

                if (!resolve_string.empty()) {
                    unsigned int space_offset=find_string(resolve_string," ");

                    while (-1!=space_offset) {
                        split=split_string(resolve_string,space_offset);
                        resolve_string=split.second;
                        left_move_string(resolve_string,1);
                        string element(split.first);
                        split=split_string(element,find_string(element,"="));
                        string element_name(split.first),element_value(split.second);
                        right_remove_space(element_name);
                        left_move_string(element_value,1);
                        left_remove_space(element_value);
                        left_remove(element_value,"\"");
                        right_remove(element_value,"\"");
                        resolve_html_set_tag_element(result,element_name,element_value);
                        space_offset=find_string(resolve_string," ");
                    }
                    string element(resolve_string);
                    split=split_string(element,find_string(element,"="));
                    string element_name(split.first),element_value(split.second);
                    right_remove_space(element_name);
                    left_move_string(element_value,1);
                    left_remove_space(element_value);
                    left_remove(element_value,"\"");
                    right_remove(element_value,"\"");
                    resolve_html_set_tag_element(result,element_name,element_value);
                }

                resolve_string=separate_string(in_string,right_flag_front+1,left_flag_back-right_flag_front-2);
                if (!resolve_string.find("\r\n"))
                    left_move_string(resolve_string,2);
                if (-1!=resolve_string.find_last_of("\r\n"))
                    split=split_string(resolve_string,resolve_string.find_last_of("\r\n"));

                resolve_html_set_tag_subtag(result,resolve_string);
            }
        }
    }
    return result;
}

tag resolve_html_to_tag(const tag in_tag) {
    string subtag(resolve_html_get_tag_subtag(in_tag));
    return resolve_html_to_tag(subtag);
}

string resolve_html_to_string(const tag& in_tag) {
    string result;

    result="<";
    result+=resolve_html_get_tag_name(in_tag);
    result+=" ";

    tag_element_list list(resolve_html_get_tag_element_list(in_tag));
    for (unsigned int index=0,last_index=resolve_html_get_tag_element_count(in_tag);index<last_index;++index) {
        result+=list[index];
        result+="=";
        result+=resolve_html_get_tag_element(in_tag,list[index]);
        result+=" ";
    }
    
    right_remove_space(result);
    result+=">";
    result+=resolve_html_get_tag_subtag(in_tag);
    result+="</";
    result+=resolve_html_get_tag_name(in_tag);
    result+=">";

    return result;
}
