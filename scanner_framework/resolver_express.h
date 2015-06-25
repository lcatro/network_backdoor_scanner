
#ifndef _RESOLVER_EXPRESS_H__
#define _RESOLVER_EXPRESS_H__


#ifndef _STRING_

#include <string>

using std::string;

#endif


/*

  element_name_1:element_value_1,element_name_2:element_value_2,element_name_3:%string%,element_name_4:%value%;string,value

*/

string resolve_express_http(const string express);

/*

    function(123123)|function(321312)
    function(function(313213123))

    function:rnd arg:[down-up]
        rnd([1-100])

*/

string resolve_express_function(const string express);


#endif

