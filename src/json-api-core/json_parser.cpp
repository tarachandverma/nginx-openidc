#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <float.h>
#include <limits.h>
#include <ctype.h>
#include <apr_strings.h>

#include "json_parser.h"

static int JSON_strcasecmp(const char *s1,const char *s2)
{
        if (!s1) return (s1==s2)?0:1;if (!s2) return 1;
        for(; tolower(*s1) == tolower(*s2); ++s1, ++s2) if(*s1 == 0)    return 0;
        return tolower(*(const unsigned char *)s1) - tolower(*(const unsigned char *)s2);
}

// The Value structure:
struct Value {
        struct Value *next,*prev;       // next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem
        struct Value *child;            // An array or object item will have a child pointer pointing to a chain of the items in the array/object.

        int type;                                       // The type of the item, as above.

        char *valuestring;                      // The item's string, if type==JSON_String
        int valueint;                           // The item's number, if type==JSON_Number
        double valuedouble;                     // The item's number, if type==JSON_Number

        char *string;                           // The item's name string, if this item is the child of, or is in the list of subitems of an object.
};

// Internal constructor.
inline Value *JSON_newValueObj(pool* p)
{
        return (Value*)apr_pcalloc(p, sizeof(Value));
}

inline Value *JSON_newValueObj(pool* p, int valueType)
{
        Value* value = (Value*)apr_pcalloc(p, sizeof(Value));
        value->type = valueType;
        return value;
}

inline Value *JSON_newValueObj(pool* p, int valueType, double num)
{
        Value* value = (Value*)apr_pcalloc(p, sizeof(Value));
        value->type = valueType;
        value->valuedouble=num;
        value->valueint=(int)num;
        return value;
}

inline Value *JSON_newValueObj(pool* p, int valueType, const char *string)
{
        Value* value = (Value*)apr_pcalloc(p, sizeof(Value));
        value->type = valueType;
        value->valuestring=apr_pstrdup(p,string);
        return value;
}
// Parse the input text to generate a number, and populate the result into item.
static const char *parse_number(pool* p,Value *item,const char *num)
{
        double n=0,sign=1,scale=0;int subscale=0,signsubscale=1;

        // Could use sscanf for this?
        if (*num=='-') sign=-1,num++;   // Has sign?
        if (*num=='0') num++;                   // is zero
        if (*num>='1' && *num<='9')     do      n=(n*10.0)+(*num++ -'0');       while (*num>='0' && *num<='9'); // Number?
        if (*num=='.') {num++;          do      n=(n*10.0)+(*num++ -'0'),scale--; while (*num>='0' && *num<='9');}      // Fractional part?
        if (*num=='e' || *num=='E')             // Exponent?
        {       num++;if (*num=='+') num++;     else if (*num=='-') signsubscale=-1,num++;              // With sign?
                while (*num>='0' && *num<='9') subscale=(subscale*10)+(*num++ - '0');   // Number?
        }

        n=sign*n*pow(10.0,(scale+subscale*signsubscale));       // number = +/- number.fraction * 10^+/- exponent

        item->valuedouble=n;
        item->valueint=(int)n;
        item->type=JSON_Number;
        return num;
}

// Render the number nicely from the given item into a string.
static char *print_number(pool* p,Value *item)
{
        char *str;
        double d=item->valuedouble;
        if (fabs(((double)item->valueint)-d)<=DBL_EPSILON && d<=INT_MAX && d>=INT_MIN)
        {
                str=(char*)apr_palloc(p, 21);    // 2^64+1 can be represented in 21 chars.
                sprintf(str,"%d",item->valueint);
        }
        else
        {
                str=(char*)apr_palloc(p, 64);    // This is a nice tradeoff.
                if (fabs(floor(d)-d)<=DBL_EPSILON)                      sprintf(str,"%.0f",d);
                else if (fabs(d)<1.0e-6 || fabs(d)>1.0e9)       sprintf(str,"%e",d);
                else                                                                            sprintf(str,"%f",d);
        }
        return str;
}

// Parse the input text into an unescaped cstring, and populate item.
static const unsigned char firstByteMark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };
static const char *parse_string(pool* p,Value *item,const char *str)
{
        const char *ptr=str+1;char *ptr2;char *out;int len=0;unsigned uc;
        if (*str!='\"') return 0;       // not a string!

        while (*ptr!='\"' && (unsigned char)*ptr>31 && ++len) if (*ptr++ == '\\') ptr++;        // Skip escaped quotes.

        out=(char*)apr_palloc(p, len+1); // This is how long we need for the string, roughly.
        if (!out) return 0;

        ptr=str+1;ptr2=out;
        while (*ptr!='\"' && (unsigned char)*ptr>31)
        {
                if (*ptr!='\\') *ptr2++=*ptr++;
                else
                {
                        ptr++;
                        switch (*ptr)
                        {
                                case 'b': *ptr2++='\b'; break;
                                case 'f': *ptr2++='\f'; break;
                                case 'n': *ptr2++='\n'; break;
                                case 'r': *ptr2++='\r'; break;
                                case 't': *ptr2++='\t'; break;
                                case 'u':        // transcode utf16 to utf8. DOES NOT SUPPORT SURROGATE PAIRS CORRECTLY.
                                        sscanf(ptr+1,"%4x",&uc);        // get the unicode char.
                                        len=3;if (uc<0x80) len=1;else if (uc<0x800) len=2;ptr2+=len;

                                        switch (len) {
                                                case 3: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
                                                case 2: *--ptr2 =((uc | 0x80) & 0xBF); uc >>= 6;
                                                case 1: *--ptr2 =(uc | firstByteMark[len]);
                                        }
                                        ptr2+=len;ptr+=4;
                                        break;
                                default:  *ptr2++=*ptr; break;
                        }
                        ptr++;
                }
        }
        *ptr2=0;
        if (*ptr=='\"') ptr++;
        item->valuestring=out;
        item->type=JSON_String;
        return ptr;
}

// Render the cstring provided to an escaped version that can be printed.
static char *print_string_ptr(pool* p,const char *str)
{
        const char *ptr;char *ptr2,*out;int len=0;

        if (!str) return apr_pstrdup(p,"");
        ptr=str;while (*ptr && ++len) {if ((unsigned char)*ptr<32 || *ptr=='\"' || *ptr=='\\') len++;ptr++;}

        out=(char*)apr_palloc(p, len+3);
        ptr2=out;ptr=str;
        *ptr2++='\"';
        while (*ptr)
        {
                if ((unsigned char)*ptr>31 && *ptr!='\"' && *ptr!='\\') *ptr2++=*ptr++;
                else
                {
                        *ptr2++='\\';
                        switch (*ptr++)
                        {
                                case '\\':      *ptr2++='\\';   break;
                                case '\"':      *ptr2++='\"';   break;
                                case '\b':      *ptr2++='b';    break;
                                case '\f':      *ptr2++='f';    break;
                                case '\n':      *ptr2++='n';    break;
                                case '\r':      *ptr2++='r';    break;
                                case '\t':      *ptr2++='t';    break;
                                default: ptr2--;        break;  // eviscerate with prejudice.
                        }
                }
        }
        *ptr2++='\"';*ptr2++=0;
        return out;
}
// Invote print_string_ptr (which is useful) on an item.
static char *print_string(pool* p,Value *item)  {return print_string_ptr(p, item->valuestring);}

// Predeclare these prototypes.
static const char *parse_value(pool* p,Value *item,const char *value);
static char *print_value(pool* p,Value *item,int depth,int fmt);
static const char *parse_array(pool* p,Value *item,const char *value);
static char *print_array(pool* p,Value *item,int depth,int fmt);
static const char *parse_object(pool* p,Value *item,const char *value);
static char *print_object(pool* p,Value *item,int depth,int fmt);

// Utility to jump whitespace and cr/lf
static const char *skip(const char *in) {while (in && (unsigned char)*in<=32) in++; return in;}

// Parse an object - create a new root, and populate.
Value* JSON_Parse(pool* p, const char *value)
{
        Value *c=JSON_newValueObj(p);
        if (!c) return NULL;       /* memory fail */

        if (!parse_value(p,c,skip(value))) {return NULL;}
        return c;
}

// Render a JSON item/entity/structure to text.
char* JSON_Serialize(pool* p,Value *item)                          {return print_value(p,item,0,1);}
char* JSON_SerializeUnformatted(pool* p,Value *item)       {return print_value(p,item,0,0);}

// Parser core - when encountering text, process appropriately.
static const char* parse_value(pool* p,Value *item,const char *value)
{
        if (!value)                                             return NULL;       // Fail on null.
        if (!strncmp(value,"null",4))   { item->type=JSON_NULL;  return value+4; }
        if (!strncmp(value,"false",5))  { item->type=JSON_False; return value+5; }
        if (!strncmp(value,"true",4))   { item->type=JSON_True; item->valueint=1;      return value+4; }
        if (*value=='\"')                               	{ return parse_string(p,item,value); }
        if (*value=='-' || (*value>='0' && *value<='9'))	{ return parse_number(p,item,value); }
        if (*value=='[')                                	{ return parse_array(p,item,value); }
        if (*value=='{')                                	{ return parse_object(p,item,value); }

        return NULL;       // failure.
}

// Render a value to text.
static char* print_value(pool* p,Value *item,int depth,int fmt)
{
        char *out=0;
        if (!item) return NULL;
        switch ((item->type)&255)
        {
                case JSON_NULL:        out=apr_pstrdup(p,"null");       break;
                case JSON_False:       out=apr_pstrdup(p,"false");break;
                case JSON_True:        out=apr_pstrdup(p,"true"); break;
                case JSON_Number:      out=print_number(p,item);break;
                case JSON_String:      out=print_string(p,item);break;
                case JSON_Array:       out=print_array(p,item,depth,fmt);break;
                case JSON_Object:      out=print_object(p,item,depth,fmt);break;
        }
        return out;
}

// Build an array from input text.
static const char* parse_array(pool* p,Value *item,const char *value)
{
        Value *child;
        if (*value!='[')        return NULL;       // not an array!

        item->type=JSON_Array;
        value=skip(value+1);
        if (*value==']') return value+1;        // empty array.

        item->child=child=JSON_newValueObj(p);
        if (!item->child) return NULL;              // memory fail
        value=skip(parse_value(p,child,skip(value)));     // skip any spacing, get the value.
        if (!value) return NULL;

        while (*value==',')
        {
                Value *new_item;
                if (!(new_item=JSON_newValueObj(p))) return NULL;     // memory fail
                child->next=new_item;new_item->prev=child;child=new_item;
                value=skip(parse_value(p,child,skip(value+1)));
                if (!value) return NULL;   // memory fail
        }

        if (*value==']') return value+1;        // end of array
        return NULL;       // malformed.
}

// Render an array to text
static char* print_array(pool* p,Value *item,int depth,int fmt)
{
        char **entries;
        char *out=0,*ptr,*ret;int len=5;
        Value *child=item->child;
        int numentries=0,i=0,fail=0;

        // How many entries in the array?
        while (child) numentries++,child=child->next;
        // Allocate an array to hold the values for each
        entries=(char**)apr_palloc(p, numentries*sizeof(char*));
        if (!entries) return 0;
        memset(entries,0,numentries*sizeof(char*));
        // Retrieve all the results:
        child=item->child;
        while (child && !fail)
        {
                ret=print_value(p,child,depth+1,fmt);
                entries[i++]=ret;
                if (ret) len+=strlen(ret)+2+(fmt?1:0); else fail=1;
                child=child->next;
        }

        // If we didn't fail, try to malloc the output string
        if (!fail) out=(char*)apr_palloc(p, len);
        // If that fails, we fail.
        if (!out) fail=1;

        // Handle failure.
        if (fail)
        {
                return 0;
        }

        // Compose the output array.
        *out='[';
        ptr=out+1;*ptr=0;
        for (i=0;i<numentries;i++)
        {
                strcpy(ptr,entries[i]);ptr+=strlen(entries[i]);
                if (i!=numentries-1) {*ptr++=',';if(fmt)*ptr++=' ';*ptr=0;}
        }
        *ptr++=']';*ptr++=0;
        return out;
}

// Build an object from the text.
static const char* parse_object(pool* p,Value *item,const char *value)
{
        Value *child;
        if (*value!='{')        return 0;       // not an object!

        item->type=JSON_Object;
        value=skip(value+1);
        if (*value=='}') return value+1;        // empty array.

        item->child=child=JSON_newValueObj(p);
        value=skip(parse_string(p,child,skip(value)));
        if (!value) return 0;
        child->string=child->valuestring;child->valuestring=0;
        if (*value!=':') return 0;      // fail!
        value=skip(parse_value(p,child,skip(value+1)));   // skip any spacing, get the value.
        if (!value) return 0;

        while (*value==',')
        {
                Value *new_item;
                if (!(new_item=JSON_newValueObj(p)))       return 0; // memory fail
                child->next=new_item;new_item->prev=child;child=new_item;
                value=skip(parse_string(p,child,skip(value+1)));
                if (!value) return 0;
                child->string=child->valuestring;child->valuestring=0;
                if (*value!=':') return 0;      // fail!
                value=skip(parse_value(p,child,skip(value+1)));   // skip any spacing, get the value.
                if (!value) return 0;
        }

        if (*value=='}') return value+1;        // end of array
        return 0;       // malformed.
}

// Render an object to text.
static char* print_object(pool* p,Value *item,int depth,int fmt)
{
        char **entries=0,**names=0;
        char *out=0,*ptr,*ret,*str;int len=7,i=0,j;
        Value *child=item->child;
        int numentries=0,fail=0;
        // Count the number of entries.
        while (child) numentries++,child=child->next;
        // Allocate space for the names and the objects
        entries=(char**)apr_palloc(p, numentries*sizeof(char*));
        if (!entries) return 0;
        names=(char**)apr_palloc(p, numentries*sizeof(char*));
        if (!names) {return 0;}
        memset(entries,0,sizeof(char*)*numentries);
        memset(names,0,sizeof(char*)*numentries);

        // Collect all the results into our arrays:
        child=item->child;depth++;if (fmt) len+=depth;
        while (child)
        {
                names[i]=str=print_string_ptr(p,child->string);
                entries[i++]=ret=print_value(p,child,depth,fmt);
                if (str && ret) len+=strlen(ret)+strlen(str)+2+(fmt?2+depth:0); else fail=1;
                child=child->next;
        }

        // Try to allocate the output string
        if (!fail) out=(char*)apr_palloc(p, len);
        if (!out) fail=1;

        // Handle failure
        if (fail)
        {
                for (i=0;i<numentries;i++) {
                	//if (names[i]) free(names[i]);
                	//if (entries[i]) free(entries[i]);
                }
                //free(names);free(entries);
                return 0;
        }

        // Compose the output:
        *out='{';ptr=out+1;if (fmt)*ptr++='\n';*ptr=0;
        for (i=0;i<numentries;i++)
        {
                if (fmt) for (j=0;j<depth;j++) *ptr++='\t';
                strcpy(ptr,names[i]);ptr+=strlen(names[i]);
                *ptr++=':';if (fmt) *ptr++='\t';
                strcpy(ptr,entries[i]);ptr+=strlen(entries[i]);
                if (i!=numentries-1) *ptr++=',';
                if (fmt) *ptr++='\n';*ptr=0;
        }

        if (fmt) for (i=0;i<depth-1;i++) *ptr++='\t';
        *ptr++='}';*ptr++=0;
        return out;
}

// Get Array size/item / object item.
int    JSON_GetArraySize(Value *array)                                                 {Value *c=array->child;int i=0;while(c)i++,c=c->next;return i;}
Value* JSON_GetArrayItem(Value *array,int item)                                {Value *c=array->child;  while (c && item>0) item--,c=c->next; return c;}
Value* JSON_GetObjectItem(Value *object,const char *string)    {Value *c=object->child; while (c && JSON_strcasecmp(c->string,string)) c=c->next; return c;}
void JSON_IterateObjectItemCallback(Value *object, void* data, peek_item_callback peekItemCallback) {
	Value *c=object->child; 
	while (c) {
		if(peekItemCallback) {
			(*peekItemCallback)(c, data);
		}
		c=c->next;
	}
}
const char* JSON_GetItemString(Value *item){
	return item->string;
}
const char* JSON_GetStringFromStringItem(Value *item){
	return item->valuestring;
}
int JSON_GetNumberFromNumberItem(Value *item){
	return item->valueint;
}
double JSON_GetDoubleFromNumberItem(Value *item) {
	return item->valuedouble;
}
int JSON_GetItemType(Value *item){
	return item->type;
}

// Utility for array list handling.
static void suffix_object(Value *prev,Value *item) {prev->next=item;item->prev=prev;}
// Utility for handling references.
static Value *create_reference(pool* p,Value *item) {Value *ref=JSON_newValueObj(p);memcpy(ref,item,sizeof(Value));ref->string=0;ref->type|=JSON_IsReference;ref->next=ref->prev=0;return ref;}

// Add item to array/object.
void JSON_AddItemToArray(pool* p,Value *array, Value *item)                                          {Value *c=array->child;if (!c) {array->child=item;} else {while (c && c->next) c=c->next; suffix_object(c,item);}}
void JSON_AddItemToObject(pool* p,Value *object,const char *string,Value *item)      {item->string=apr_pstrdup(p,string);JSON_AddItemToArray(p,object,item);}
void JSON_AddItemReferenceToArray(pool* p,Value *array, Value *item)                                                {JSON_AddItemToArray(p,array,create_reference(p,item));}
void JSON_AddItemReferenceToObject(pool* p,Value *object,const char *string,Value *item)    {JSON_AddItemToObject(p,object,string,create_reference(p,item));}

Value* JSON_DetachItemFromArray(Value *array,int which)                        {Value *c=array->child;while (c && which>0) c=c->next,which--;if (!c) return 0;
        if (c->prev) c->prev->next=c->next;if (c->next) c->next->prev=c->prev;if (c==array->child) array->child=c->next;c->prev=c->next=0;return c;}
void   JSON_DeleteItemFromArray(Value *array,int which)                        {JSON_DetachItemFromArray(array,which);}
Value* JSON_DetachItemFromObject(Value *object,const char *string) {int i=0;Value *c=object->child;while (c && JSON_strcasecmp(c->string,string)) i++,c=c->next;if (c) return JSON_DetachItemFromArray(object,i);return 0;}
void   JSON_DeleteItemFromObject(Value *object,const char *string) {JSON_DetachItemFromObject(object,string);}

// Replace array/object items with new ones.
void   JSON_ReplaceItemInArray(Value *array,int which,Value *newitem)          {Value *c=array->child;while (c && which>0) c=c->next,which--;if (!c) return;
        newitem->next=c->next;newitem->prev=c->prev;if (newitem->next) newitem->next->prev=newitem;
        if (c==array->child) array->child=newitem; else newitem->prev->next=newitem;c->next=c->prev=0;}
void   JSON_ReplaceItemInObject(pool* p, Value *object,const char *string,Value *newitem){int i=0;Value *c=object->child;while(c && JSON_strcasecmp(c->string,string))i++,c=c->next;if(c){newitem->string=apr_pstrdup(p,string);JSON_ReplaceItemInArray(object,i,newitem);}}

// Create basic types:
Value* JSON_CreateNull(pool* p)				{ return JSON_newValueObj(p,JSON_NULL); }
Value* JSON_CreateTrue(pool* p)             { return JSON_newValueObj(p,JSON_True); }
Value* JSON_CreateFalse(pool* p)            { return JSON_newValueObj(p,JSON_False); }
Value* JSON_CreateNumber(pool* p,
		double num)            				{ return JSON_newValueObj(p, JSON_Number,num); }
Value* JSON_CreateString(pool* p,
		const char *string)   				{ return JSON_newValueObj(p, JSON_String, string); }
Value* JSON_CreateArray(pool* p)            { return JSON_newValueObj(p,JSON_Array); }
Value* JSON_CreateObject(pool* p)           { return JSON_newValueObj(p,JSON_Object); }

// Create Arrays:
Value* JSON_CreateIntArray(pool*_pool,int *numbers,int count)				{int i;Value *n=0,*p=0,*a=JSON_CreateArray(_pool);for(i=0;i<count;i++){n=JSON_CreateNumber(_pool,numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
Value* JSON_CreateFloatArray(pool*_pool,float *numbers,int count)       	{int i;Value *n=0,*p=0,*a=JSON_CreateArray(_pool);for(i=0;i<count;i++){n=JSON_CreateNumber(_pool,numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
Value* JSON_CreateDoubleArray(pool*_pool,double *numbers,int count)     	{int i;Value *n=0,*p=0,*a=JSON_CreateArray(_pool);for(i=0;i<count;i++){n=JSON_CreateNumber(_pool,numbers[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}
Value* JSON_CreateStringArray(pool*_pool,const char **strings,int count)	{int i;Value *n=0,*p=0,*a=JSON_CreateArray(_pool);for(i=0;i<count;i++){n=JSON_CreateString(_pool,strings[i]);if(!i)a->child=n;else suffix_object(p,n);p=n;}return a;}

