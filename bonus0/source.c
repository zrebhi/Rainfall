#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Function prototypes
void p(char *buffer, char *prompt);
void pp(char *dest);

int main(void)
{
  char buffer[54];
  
  pp(buffer);
  puts(buffer);
  return 0;
}

void pp(char *dest)
{
  char first_input[20];
  char second_input[20];
  char current_char;
  unsigned int length;
  char *str_ptr;
  unsigned char flag;
  
  flag = 0;
  p(first_input, " - ");
  p(second_input, " - ");
  
  strcpy(dest, first_input);
  
  // Find the end of the string
  length = 4294967295;
  str_ptr = dest;
  do {
    if (length == 0) break;
    length--;
    current_char = *str_ptr;
    str_ptr = str_ptr + (unsigned int)flag * -2 + 1;
  } while (current_char != '\0');
  
  // Add space character at end of string
  dest[~length - 1] = ' ';
  dest[~length] = '\0';
  
  strcat(dest, second_input);
  return;
}

void p(char *buffer, char *prompt)
{
  char *newline_ptr;
  char input_buffer[4104];
  
  puts(prompt);
  read(0, input_buffer, 4096);
  newline_ptr = strchr(input_buffer, '\n');
  *newline_ptr = '\0';
  strncpy(buffer, input_buffer, 20);
  return;
}

