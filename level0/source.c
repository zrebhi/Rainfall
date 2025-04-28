#include <stdlib.h>  // for atoi
#include <string.h>  // for strdup
#include <unistd.h>  // for getegid, geteuid, setresgid, setresuid, execv
#include <stdio.h>   // for fwrite and stderr
#include <sys/types.h> // for __uid_t and __gid_t

int main(int argc, char *argv[])
{
  int inputNumber;
  char *shellCommand;
  char *envp;
  __uid_t effectiveUserID;
  __gid_t effectiveGroupID;
  
  // Convert the first argument to integer
  inputNumber = atoi(argv[1]);
  
  // Check if the input number equals 423 (0x1a7 in hex)
  if (inputNumber == 423) {
    // Prepare to execute a shell
    shellCommand = strdup("/bin/sh");
    envp = NULL;
    
    // Get current effective group and user IDs
    effectiveGroupID = getegid();
    effectiveUserID = geteuid();
    
    // Set real, effective, and saved group/user IDs
    setresgid(effectiveGroupID, effectiveGroupID, effectiveGroupID);
    setresuid(effectiveUserID, effectiveUserID, effectiveUserID);
    
    // Execute the shell
    execv("/bin/sh", &shellCommand);
  }
  else {
    // Print error message if input is incorrect
    fwrite("No !\n", 1, 5, stderr);
  }
  
  return 0;
}