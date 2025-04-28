#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

char *auth = NULL;
char *service = NULL;


/*
 * Simplified version of main that maintains the same vulnerability
 * but with more readable code
 */
int simplified_main(void) {
    char input_buffer[128];
    
    while (true) {
        // Display current pointer values
        printf("%p, %p \n", auth, service);
        
        // Get user input
        if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
            return 0;
        }
        
        // Handle "auth " command - allocates small buffer and copies user input
        if (strncmp(input_buffer, "auth ", 5) == 0) {
            auth = malloc(4);  // Only allocates 4 bytes!
            
            // Initialize buffer with zeros
            memset(auth, 0, 4);
            
            // Copy parameter if length is reasonable
            char *param = input_buffer + 5;  // Skip "auth " prefix
            if (strlen(param) <= 30) {
                strcpy(auth, param);  // No bounds checking!
            }
        }
        // Handle "reset" command - frees the auth pointer
        else if (strncmp(input_buffer, "reset", 5) == 0) {
            free(auth);
            auth = NULL;
        }
        // Handle "service" command - duplicates the parameter into service
        else if (strncmp(input_buffer, "service", 7) == 0) {
            service = strdup(input_buffer + 7);  // Skip "service" prefix
        }
        // Handle "login" command - checks auth+0x20 and potentially runs shell
        else if (strncmp(input_buffer, "login", 5) == 0) {
            // Vulnerability: auth is only 4 bytes but we check 32 bytes past it
            if (auth != NULL && *(int*)(auth + 32) != 0) {
                system("/bin/sh");
            } else {
                fwrite("Password:\n", 1, 10, stdout);
            }
        }
    }
    
    return 0;
}

int main(void)
{
  char current_char;
  char *auth_ptr1;
  char *auth_ptr2;
  char *input_line;
  int compare_counter;
  unsigned int str_length;
  unsigned char *cmd_ptr;
  unsigned char *compare_str_ptr;
  bool is_less_than;
  unsigned char result1;
  unsigned char result2;
  bool is_equal;
  unsigned char result3;
  unsigned char zero_flag;
  unsigned char input_buffer[5];
  char auth_param[2];
  char service_param[125];
  
  zero_flag = 0;
  do {
    printf("%p, %p \n", auth, service);
    input_line = fgets((char *)input_buffer, 0x80, stdin);
    is_less_than = false;
    is_equal = input_line == (char *)0x0;
    if (is_equal) {
      return 0;
    }
    compare_counter = 5;
    cmd_ptr = input_buffer;
    compare_str_ptr = (unsigned char *)"auth ";
    do {
      if (compare_counter == 0) break;
      compare_counter = compare_counter + -1;
      is_less_than = *cmd_ptr < *compare_str_ptr;
      is_equal = *cmd_ptr == *compare_str_ptr;
      cmd_ptr = cmd_ptr + (unsigned int)zero_flag * -2 + 1;
      compare_str_ptr = compare_str_ptr + (unsigned int)zero_flag * -2 + 1;
    } while (is_equal);
    result1 = 0;
    result3 = (!is_less_than && !is_equal) == is_less_than;
    if ((bool)result3) {
      auth = (char *)malloc(4);
      auth_ptr1 = auth + 1;
      auth_ptr2 = auth + 2;
      input_line = auth + 3;
      auth[0] = '\0';
      *auth_ptr1 = '\0';
      *auth_ptr2 = '\0';
      *input_line = '\0';
      str_length = 0xffffffff;
      input_line = auth_param;
      do {
        if (str_length == 0) break;
        str_length = str_length - 1;
        current_char = *input_line;
        input_line = input_line + (unsigned int)zero_flag * -2 + 1;
      } while (current_char != '\0');
      str_length = ~str_length - 1;
      result1 = str_length < 0x1e;
      result3 = str_length == 0x1e;
      if (str_length < 0x1f) {
        strcpy(auth, auth_param);
      }
    }
    compare_counter = 5;
    cmd_ptr = input_buffer;
    compare_str_ptr = (unsigned char *)"reset";
    do {
      if (compare_counter == 0) break;
      compare_counter = compare_counter + -1;
      result1 = *cmd_ptr < *compare_str_ptr;
      result3 = *cmd_ptr == *compare_str_ptr;
      cmd_ptr = cmd_ptr + (unsigned int)zero_flag * -2 + 1;
      compare_str_ptr = compare_str_ptr + (unsigned int)zero_flag * -2 + 1;
    } while ((bool)result3);
    result2 = 0;
    result1 = (!(bool)result1 && !(bool)result3) == (bool)result1;
    if ((bool)result1) {
      free(auth);
    }
    compare_counter = 6;
    cmd_ptr = input_buffer;
    compare_str_ptr = (unsigned char *)"service";
    do {
      if (compare_counter == 0) break;
      compare_counter = compare_counter + -1;
      result2 = *cmd_ptr < *compare_str_ptr;
      result1 = *cmd_ptr == *compare_str_ptr;
      cmd_ptr = cmd_ptr + (unsigned int)zero_flag * -2 + 1;
      compare_str_ptr = compare_str_ptr + (unsigned int)zero_flag * -2 + 1;
    } while ((bool)result1);
    result3 = 0;
    result1 = (!(bool)result2 && !(bool)result1) == (bool)result2;
    if ((bool)result1) {
      result3 = (unsigned char *)0xfffffff8 < input_buffer;
      result1 = service_param == (char *)0x0;
      service = strdup(service_param);
    }
    compare_counter = 5;
    cmd_ptr = input_buffer;
    compare_str_ptr = (unsigned char *)"login";
    do {
      if (compare_counter == 0) break;
      compare_counter = compare_counter + -1;
      result3 = *cmd_ptr < *compare_str_ptr;
      result1 = *cmd_ptr == *compare_str_ptr;
      cmd_ptr = cmd_ptr + (unsigned int)zero_flag * -2 + 1;
      compare_str_ptr = compare_str_ptr + (unsigned int)zero_flag * -2 + 1;
    } while ((bool)result1);
    if ((!(bool)result3 && !(bool)result1) == (bool)result3) {
      if (*(int *)(auth + 0x20) == 0) {
        fwrite("Password:\n", 1, 10, stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while(true);
}
