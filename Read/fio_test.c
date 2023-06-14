// Define the FIO command as a string
const char* fioCommand = "fio test.fio";

// Execute the FIO command
int result = system(fioCommand);
//execl("/bin/sh", "sh", "-c", fioCommand, NULL);

if (result == -1) {
  printf("Failed to execute FIO command.\n");
  goto cleanup;
}
