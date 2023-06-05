Observations so far :
  1. In a seq read i have noticed that mark_page_access = sync_ra + async_ra + 1
  2. In a rand read i have noticed that mark_page_access > sync_ra and almost every time async_ra = 0

Questions : 
  1. I am not sure about copy_to_page_iter because :
    1. Do i count a page access when copy_to_page_iter returns 0
    2. If i don't count it when it returns 0 then copy_to_page_iter = sync_ra + async_ra
    3. if i count it then copy_to_page_iter depends on block size
