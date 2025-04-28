#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h> // Needed for uint cast in original loop logic

int main(int argc, char *argv[]) {
    int return_status;          // was uVar1 (undefined4)
    int loop_counter;           // was iVar2 (used in loop)
    char *buffer_ptr;           // was pcVar3
    unsigned char zero_flag;    // was bVar4 (byte) - assuming unsigned char
    char password_buffer[65];   // was local_98
    char null_terminator_byte;  // was local_57 (undefined1)
    char message_buffer[66];    // was local_56
    FILE *password_file;        // was local_14
    int password_len_arg;       // was iVar2 (used for atoi result)
    int comparison_result;      // was iVar2 (used for strcmp result)

    zero_flag = 0;
    password_file = fopen("/home/user/end/.pass", "r");
    buffer_ptr = password_buffer;

    // Original initialization loop - preserved exactly
    for (loop_counter = 33; loop_counter != 0; loop_counter = loop_counter + -1) { // 0x21 -> 33
        buffer_ptr[0] = '\0';
        buffer_ptr[1] = '\0';
        buffer_ptr[2] = '\0';
        buffer_ptr[3] = '\0';
        // Preserving original pointer arithmetic exactly, including the cast
        buffer_ptr = buffer_ptr + ((unsigned int)zero_flag * -2 + 1) * 4;
    }

    // Check file and argument count
    if ((password_file == NULL) || (argc != 2)) { // 0x0 -> NULL
        return_status = -1; // 0xffffffff -> -1
    } else {
        // Read operations
        fread(password_buffer, 1, 66, password_file); // 0x42 -> 66
        null_terminator_byte = 0; // Original line 29

        // Argument processing and buffer manipulation
        password_len_arg = atoi(argv[1]); // Use argv[1]
        password_buffer[password_len_arg] = '\0'; // The key vulnerability manipulation

        // Second read and close
        fread(message_buffer, 1, 65, password_file); // 0x41 -> 65
        fclose(password_file);

        // Comparison and conditional execution
        comparison_result = strcmp(password_buffer, argv[1]); // Use argv[1]
        if (comparison_result == 0) {
            execl("/bin/sh", "sh", (char *)NULL); // 0 -> (char *)NULL
        } else {
            puts(message_buffer);
        }
        return_status = 0;
    }
    return return_status;
}