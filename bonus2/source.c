#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variable
int language = 0;

int main(int argc, char **argv)
{
  int result;
  int comp_result;
  char *str_ptr;
  int *dst_ptr;
  char username[40];
  char message[36];
  char *lang_env;
  
  if (argc == 3) {
    // Initialize username buffer with zeros
    str_ptr = username;
    for (int i = 19; i != 0; i--) {
      str_ptr[0] = '\0';
      str_ptr[1] = '\0';
      str_ptr[2] = '\0';
      str_ptr[3] = '\0';
      str_ptr += 4;
    }
    
    // Copy command line arguments to buffers
    strncpy(username, argv[1], 40);
    strncpy(message, argv[2], 32);
    
    // Check LANG environment variable
    lang_env = getenv("LANG");
    if (lang_env != NULL) {
      comp_result = memcmp(lang_env, "fi", 2);
      if (comp_result == 0) {
        language = 1;
      } else {
        comp_result = memcmp(lang_env, "nl", 2);
        if (comp_result == 0) {
          language = 2;
        }
      }
    }
    
    // Copy username to the stack
    str_ptr = username;
    dst_ptr = (int *)&username; // This is likely wrong in the decompiled code
                               // Should be copying to a different memory location
    for (int i = 19; i != 0; i--) {
      *dst_ptr = *(int *)str_ptr;
      str_ptr += 4;
      dst_ptr += 1;
    }
    
    greetuser();
    result = 0;
  } else {
    result = 1;
  }
  
  return result;
}

void greetuser(void)
{
  char greeting[4];
  char greeting_continuation[4];
  char message[64];
  
  if (language == 1) {
    // Finnish greeting
    greeting[0] = 'H';
    greeting[1] = 'y';
    greeting[2] = 'v';
    greeting[3] = 0xC3; // ä character (first byte)
    greeting_continuation[0] = 0xA4; // ä character (second byte)
    greeting_continuation[1] = 0xC3; // ä character (first byte)
    greeting_continuation[2] = 0xA4; // ä character (second byte)
    greeting_continuation[3] = ' ';
    strncpy(message, "päivää ", 11);
  } else if (language == 2) {
    // Dutch greeting
    strncpy(greeting, "Goed", 4);
    greeting_continuation[0] = 'e';
    greeting_continuation[1] = 'm';
    greeting_continuation[2] = 'i';
    greeting_continuation[3] = 'd';
    strncpy(message, "dag!", 4);
    message[4] = ' ';
    message[5] = '\0';
  } else if (language == 0) {
    // English greeting
    strncpy(greeting, "Hell", 4);
    greeting_continuation[0] = 'o';
    greeting_continuation[1] = ' ';
    greeting_continuation[2] = '\0';
    greeting_continuation[3] = '\0';
  }
  
  // Concatenate the greeting with the user-provided message
  strcat(greeting, greeting_continuation);
  puts(greeting);
  
  return;
}