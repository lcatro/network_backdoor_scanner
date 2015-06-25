
#ifndef _RESOLVER_HTML_H__
#define _RESOLVER_HTML_H__


#ifndef _STRING_

#include <string>

using std::string;

#endif

#ifndef _PAIR_
#define _PAIR_

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


#define HTML_TAG_NAME "HTML_TAG_NAME"
#define HTML_TAG_SUBTAG "HTML_TAG_SUBTAG"

typedef map<string,string> tag_data;      //  tag_name,tag_subtag
typedef map<string,string> tag_element;   //  all tag element
typedef vector<string> tag_element_list;
typedef pair<tag_data,tag_element> tag;


tag              resolve_html_to_tag(const string in_string);
tag              resolve_html_to_tag(const tag in_tag);
string           resolve_html_to_string(const tag& in_tag);

bool             resolve_html_is_empty(const tag& in_tag);
string           resolve_html_get_tag_name(const tag& in_tag);
void             resolve_html_set_tag_name(tag& in_tag,const string tag_name);
string           resolve_html_get_tag_subtag(const tag& in_tag);
void             resolve_html_set_tag_subtag(tag& in_tag,const string tag_subtag);
unsigned int     resolve_html_get_tag_element_count(const tag& in_tag);
tag_element_list resolve_html_get_tag_element_list(const tag& in_tag);
string           resolve_html_get_tag_element(const tag& in_tag,const string element_name);
void             resolve_html_set_tag_element(tag& in_tag,const string element_name,const string element_value);
void             resolve_html_delete_tag_element(tag& in_tag,const string element_name);

#endif
