#ifndef JSON_PARSER_H
#define JSON_PARSER_H
#include "apache_typedefs.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum {
	JSON_False=0,
	JSON_True=1,
	JSON_NULL=2,
	JSON_Number=3,
	JSON_String=4,
	JSON_Array=5,
	JSON_Object=6
};

#define JSON_IsReference 256

//Forward declaration.

typedef struct Value Value;

// Supply a block of JSON, and this returns a JSON object you can interrogate.
Value* JSON_Parse(pool* p, const char *value);
// Render a JSON entity to text for transfer/storage.
char* JSON_Serialize(pool* p, Value *item);
// Render a JSON entity to text for transfer/storage without any formatting.
char* JSON_SerializeUnformatted(pool* p,Value *item);

// Returns the number of items in an array (or object).
int	JSON_GetArraySize(Value *array);
// Retrieve item number "item" from array "array". Returns NULL if unsuccessful.
Value* JSON_GetArrayItem(Value *array,int item);
// Get item "string" from object. Case insensitive.
Value* JSON_GetObjectItem(Value *object,const char *string);

typedef void (*peek_item_callback) (Value* value, void* data);
void JSON_IterateObjectItemCallback(Value *object, void* data, peek_item_callback peekItemCallback);

// Get item string.
const char* JSON_GetItemString(Value *item);
// Get string fron string type item.
const char* JSON_GetStringFromStringItem(Value *item);
// Get number fron number item.
int JSON_GetNumberFromNumberItem(Value *item);
// Get double fron number item.
double JSON_GetDoubleFromNumberItem(Value *item);
// Get item type.
int JSON_GetItemType(Value *item);

// These calls create a JSON item of the appropriate type.
Value* JSON_CreateNull(pool* p);
Value* JSON_CreateTrue(pool* p);
Value* JSON_CreateFalse(pool* p);
Value* JSON_CreateNumber(pool* p,double num);
Value* JSON_CreateString(pool* p,const char *string);
Value* JSON_CreateArray(pool* p);
Value* JSON_CreateObject(pool* p);

// These utilities create an Array of count items.
Value* JSON_CreateIntArray(pool* p,int *numbers,int count);
Value* JSON_CreateFloatArray(pool* p,float *numbers,int count);
Value* JSON_CreateDoubleArray(pool* p,double *numbers,int count);
Value* JSON_CreateStringArray(pool* p,const char **strings,int count);

// Append item to the specified array/object.
void JSON_AddItemToArray(pool* p,Value *array, Value *item);
void JSON_AddItemToObject(pool* p,Value *object,const char *string,Value *item);
// Append reference to item to the specified array/object. Use this when you want to add an existing JSON to a new JSON, but don't want to corrupt your existing JSON.
void JSON_AddItemReferenceToArray(pool* p,Value *array, Value *item);
void JSON_AddItemReferenceToObject(pool* p,Value *object,const char *string,Value *item);

// Remove/Detatch items from Arrays/Objects.
Value* JSON_DetachItemFromArray(Value *array,int which);
void   JSON_DeleteItemFromArray(Value *array,int which);
Value* JSON_DetachItemFromObject(Value *object,const char *string);
void   JSON_DeleteItemFromObject(Value *object,const char *string);

// Update array items.
void JSON_ReplaceItemInArray(Value *array,int which,Value *newitem);
void JSON_ReplaceItemInObject(pool* p,Value *object,const char *string,Value *newitem);

#define JSON_AddNullToObject(p,object,name)      JSON_AddItemToObject(p,object, name, JSON_CreateNull(p))
#define JSON_AddTrueToObject(p,object,name)      JSON_AddItemToObject(p,object, name, JSON_CreateTrue(p))
#define JSON_AddFalseToObject(p,object,name)     JSON_AddItemToObject(p,object, name, JSON_CreateFalse(p))
#define JSON_AddNumberToObject(p,object,name,n)  JSON_AddItemToObject(p,object, name, JSON_CreateNumber(p,n))
#define JSON_AddStringToObject(p,object,name,s)  JSON_AddItemToObject(p,object, name, JSON_CreateString(p,s))

#ifdef __cplusplus
}
#endif

#endif // #if JSON_PARSER_H

