/**
 * I hate magic numbers!
 * 
 * This header contains common macros.
 *
 * Author: Hamster Tian <haotia@gmail.com>
 * Date: 2015/07/03
 */
 
#ifndef PROXY_CONST_H
#define PROXY_CONST_H

#define STRINGIFY(x) _STRINGIFY(x)
#define _STRINGIFY(x) #x

#define TRUE 1
#define FALSE 0
 
#define EXIT_NO_ERROR 0
 
#define RESULT_FAIL -1
#define RESULT_OK 0

#define VERSION 0.1
/* Uncomment if needed
 #define SPECIAL_THANKS "Special thanks to xxx\n"
 */
 
#define MAX_STRING_PARAM_LENGTH 1024

#define DEFAULT_REQUIRED_SUCCESS_COUNT 1

#endif