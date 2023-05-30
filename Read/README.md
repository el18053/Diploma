Three case studies :

1) Sequential access (read_file.c)  : 
  *There will be one Page Cache miss first time the file gets accessed
  *Due to Page Cache async Read Ahead there will not be another Page Cache Miss
2) Reverse access (readfilereverse.c) :
  *Due to the fact that we read the file from end to start Page Cache Read Ahead will always fail
  *There will be a Page Cache miss in every pread() sys call
3) Mapping the file (mmap_read.c) :
  *In this case we first map the file
  *After that we access the mapped area so that the MMU will actually fetch the data to the Page Cache
  *We use pread() sys call to read the file and due to the fact that the file is already in the Page Cache there will not be any Page Cache misses
  *(There will not be any async Read Aheads eiter!)
