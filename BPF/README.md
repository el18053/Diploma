Observations so far :
  1. In a seq read i have noticed that mark_page_access = sync_ra + async_ra + 1
  2. In a rand read i have noticed that mark_page_access > sync_ra and almost every time async_ra = 0
