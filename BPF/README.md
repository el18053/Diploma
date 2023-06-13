Observations so far :
  1. In a seq read i have noticed that mark_page_access = sync_ra + async_ra + 1
  2. In a rand read i have noticed that mark_page_access > sync_ra and almost every time async_ra = 0
  3. We see in the linux kernel in the function filemap_read the following :
    "/*
		 * When a sequential read accesses a page several times, only
		 * mark it as accessed the first time.
		 */
		if (iocb->ki_pos >> PAGE_SHIFT !=
		    ra->prev_pos >> PAGE_SHIFT)
			mark_page_accessed(pvec.pages[0]);"
      If we comment out ONLY the if() (not the mark_page_accessed) then we see that mark_page_access = copy_to_page_iter  
  4. I think that force_page_cache_ra is executed if we use fadvise to notify the kernel that he should go ahead and start the readahead process. Otherwise i think that ondemand_readahead will take care of the readahead.
  5. I think that filemap_get_read_batch() reads a batch of pages from the page cache and add them to pvec(). After that we can access them from pvec().

Questions : 
  1. I am not sure about copy_to_page_iter because :
  
      1. Do i count a page access when copy_to_page_iter returns 0
      2. If i don't count it when it returns 0 then copy_to_page_iter = sync_ra + async_ra
      3. if i count it then copy_to_page_iter depends on block size
