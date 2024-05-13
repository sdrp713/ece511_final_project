//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "edge_call.h"
#include <syscall.h>

#define OCALL_PRINT_STRING 1
#define WORDS_COUNT 2

unsigned long ocall_print_string(char* string);
int var;
int count;

int main(){
  var = 1;
  ocall_print_string("Hello World");
  register_call(WORDS_COUNT, word_count);
  while(var) {}
  ocall_print_string(count);
  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}

void word_count(char* buffer){

  int len = strlen(buffer);
  char* cur;
  size_t count = 0;
  int prev_whitespace = 1;
  cur = buffer;
  while(*cur != '\0' && len > 0){
    if(	(*cur == ' ' ||
  	 *cur == '\n' ||
  	 *cur == '\t')){
      if( prev_whitespace == 0 ){
  	count++;
  	prev_whitespace = 1;
      }
    }
    else{
      prev_whitespace = 0;
    }
    cur++;
    len--;
  }
  if(prev_whitespace == 0)
    count++;
  var = 0;
}