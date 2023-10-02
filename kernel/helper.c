BPF_CALL_2(bpf_simos, struct kiocb *, iocb, struct bpf_map *, map)
{

	unsigned long i = 0;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());
	unsigned long *nr_pages = (unsigned long) map->ops->map_lookup_elem(map, &i);
	int *indexes = kzalloc(*nr_pages*sizeof(int), GFP_ATOMIC);//int indexes[*nr_pages];
	if (nr_pages != NULL)
	{
		for(i=1; i <= *nr_pages; i++)
		{
			WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());
			unsigned long *index = (unsigned long) map->ops->map_lookup_elem(map, &i);
			indexes[i-1] = *index;
		}

	}

	struct file *filp = iocb->ki_filp;
	struct address_space *mapping = filp->f_mapping;
	struct file_ra_state *ra = &filp->f_ra;
	DEFINE_READAHEAD(ractl, filp, ra, mapping, 0);
	my_custom_function_2(&ractl, *nr_pages, indexes);
	kfree(indexes);
	return 0;
}

const struct bpf_func_proto bpf_simos_proto = {
	.func		= bpf_simos,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
};
