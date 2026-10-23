// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2015 Intel Corporation. All rights reserved. */
#include <linux/device.h>
#include <linux/io.h>
#include <linux/kasan.h>
#include <linux/memory_hotplug.h>
#include <linux/memremap.h>
#include <linux/swap.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/swapops.h>
#include <linux/types.h>
#include <linux/wait_bit.h>
#include <linux/xarray.h>
#include "internal.h"

static DEFINE_XARRAY(pgmap_array);

/*
 * The memremap() and memremap_pages() interfaces are alternately used
 * to map persistent memory namespaces. These interfaces place different
 * constraints on the alignment and size of the mapping (namespace).
 * memremap() can map individual PAGE_SIZE pages. memremap_pages() can
 * only map subsections (2MB), and at least one architecture (PowerPC)
 * the minimum mapping granularity of memremap_pages() is 16MB.
 *
 * The role of memremap_compat_align() is to communicate the minimum
 * arch supported alignment of a namespace such that it can freely
 * switch modes without violating the arch constraint. Namely, do not
 * allow a namespace to be PAGE_SIZE aligned since that namespace may be
 * reconfigured into a mode that requires SUBSECTION_SIZE alignment.
 */
#ifndef CONFIG_ARCH_HAS_MEMREMAP_COMPAT_ALIGN
unsigned long memremap_compat_align(void)
{
	return SUBSECTION_SIZE;
}
EXPORT_SYMBOL_GPL(memremap_compat_align);
#endif

static void pgmap_array_delete(struct range *range)
{
	xa_store_range(&pgmap_array, PHYS_PFN(range->start), PHYS_PFN(range->end),
			NULL, GFP_KERNEL);
	synchronize_rcu();
}

static unsigned long pfn_first(struct dev_pagemap *pgmap, int range_id)
{
	struct range *range = &pgmap->ranges[range_id];
	unsigned long pfn = PHYS_PFN(range->start);

	if (range_id)
		return pfn;
	return pfn + vmem_altmap_offset(pgmap_altmap(pgmap));
}

bool pgmap_pfn_valid(struct dev_pagemap *pgmap, unsigned long pfn)
{
	int i;

	for (i = 0; i < pgmap->nr_range; i++) {
		struct range *range = &pgmap->ranges[i];

		if (pfn >= PHYS_PFN(range->start) &&
		    pfn <= PHYS_PFN(range->end))
			return pfn >= pfn_first(pgmap, i);
	}

	return false;
}

static unsigned long pfn_end(struct dev_pagemap *pgmap, int range_id)
{
	const struct range *range = &pgmap->ranges[range_id];

	return (range->start + range_len(range)) >> PAGE_SHIFT;
}

static unsigned long pfn_len(struct dev_pagemap *pgmap, unsigned long range_id)
{
	return (pfn_end(pgmap, range_id) -
		pfn_first(pgmap, range_id)) >> pgmap->vmemmap_shift;
}

static void pageunmap_range(struct dev_pagemap *pgmap, int range_id)
{
	struct range *range = &pgmap->ranges[range_id];
	struct page *first_page;

	/* make sure to access a memmap that was actually initialized */
	first_page = pfn_to_page(pfn_first(pgmap, range_id));

	/* pages are dead and unused, undo the arch mapping */
	mem_hotplug_begin();
	remove_pfn_range_from_zone(page_zone(first_page), PHYS_PFN(range->start),
				   PHYS_PFN(range_len(range)));
	if (pgmap->type == MEMORY_DEVICE_PRIVATE) {
		__remove_pages(PHYS_PFN(range->start),
			       PHYS_PFN(range_len(range)), NULL);
	} else {
		arch_remove_memory(range->start, range_len(range),
				pgmap_altmap(pgmap));
		kasan_remove_zero_shadow(__va(range->start), range_len(range));
	}
	mem_hotplug_done();

	pfnmap_untrack(PHYS_PFN(range->start), range_len(range));
	pgmap_array_delete(range);
}

void memunmap_pages(struct dev_pagemap *pgmap)
{
	int i;

	percpu_ref_kill(&pgmap->ref);
	if (pgmap->type != MEMORY_DEVICE_PRIVATE &&
	    pgmap->type != MEMORY_DEVICE_COHERENT)
		for (i = 0; i < pgmap->nr_range; i++)
			percpu_ref_put_many(&pgmap->ref, pfn_len(pgmap, i));

	wait_for_completion(&pgmap->done);

	for (i = 0; i < pgmap->nr_range; i++)
		pageunmap_range(pgmap, i);
	percpu_ref_exit(&pgmap->ref);

	WARN_ONCE(pgmap->altmap.alloc, "failed to free all reserved pages\n");
}
EXPORT_SYMBOL_GPL(memunmap_pages);

static void devm_memremap_pages_release(void *data)
{
	memunmap_pages(data);
}

static void dev_pagemap_percpu_release(struct percpu_ref *ref)
{
	struct dev_pagemap *pgmap = container_of(ref, struct dev_pagemap, ref);

	complete(&pgmap->done);
}

static int pagemap_range(struct dev_pagemap *pgmap, struct mhp_params *params,
		int range_id, int nid)
{
	const bool is_private = pgmap->type == MEMORY_DEVICE_PRIVATE;
	struct range *range = &pgmap->ranges[range_id];
	struct dev_pagemap *conflict_pgmap;
	int error, is_ram;

	if (WARN_ONCE(pgmap_altmap(pgmap) && range_id > 0,
				"altmap not supported for multiple ranges\n"))
		return -EINVAL;

	conflict_pgmap = get_dev_pagemap(PHYS_PFN(range->start));		//检测start地址是否落在已分配的地址范围内，即判断是否跟已有的pgmap冲突，冲突则报错return
	if (conflict_pgmap) {
		WARN(1, "Conflicting mapping in same section\n");
		put_dev_pagemap(conflict_pgmap);
		return -ENOMEM;
	}

	conflict_pgmap = get_dev_pagemap(PHYS_PFN(range->end));			//检测end地址是否落在已分配的地址范围内，即判断是否跟已有的pgmap冲突，冲突则报错return
	if (conflict_pgmap) {
		WARN(1, "Conflicting mapping in same section\n");
		put_dev_pagemap(conflict_pgmap);
		return -ENOMEM;
	}

	//该函数检查resource是否重叠(或者说是否覆盖system RAM)
	is_ram = region_intersects(range->start, range_len(range),	IORESOURCE_SYSTEM_RAM, IORES_DESC_NONE);

	//DISJOINT是完全不重叠
	if (is_ram != REGION_DISJOINT) {
		WARN_ONCE(1, "attempted on %s region %#llx-%#llx\n",
				is_ram == REGION_MIXED ? "mixed" : "ram",
				range->start, range->end);
		return -ENXIO;
	}

	//把该pfn范围存放到全局变量pgmap_array中
	error = xa_err(xa_store_range(&pgmap_array, PHYS_PFN(range->start),
				PHYS_PFN(range->end), pgmap, GFP_KERNEL));
	if (error)
		return error;

	if (nid < 0)
		nid = numa_mem_id();

	//用于追踪记录pgprot
	error = pfnmap_track(PHYS_PFN(range->start), range_len(range),
			     &params->pgprot);
	if (error)
		goto err_pfn_remap;

	if (!mhp_range_allowed(range->start, range_len(range), !is_private)) {
		error = -EINVAL;
		goto err_kasan;
	}

	mem_hotplug_begin();

	/*
	 * For device private memory we call add_pages() as we only need to
	 * allocate and initialize struct page for the device memory. More-
	 * over the device memory is un-accessible thus we do not want to
	 * create a linear mapping for the memory like arch_add_memory()
	 * would do.
	 *
	 * For all other device memory types, which are accessible by
	 * the CPU, we do want the linear mapping and thus use
	 * arch_add_memory().
	 */
	//如果是MEMORY_DEVICE_PRIVATE类型的内存，调用add_pages函数；否则调用arch_add_memory汉斯
	//add_pages是只初始化/建立memmap和page metadata(元数据)，不会建立CPU用的直接映射(direct map)
	//arch_add_memory是会建立direct/linear map，并且应用pgprot属性
	if (is_private) {
		error = add_pages(nid, PHYS_PFN(range->start),
				PHYS_PFN(range_len(range)), params);
	} else {
		error = kasan_add_zero_shadow(__va(range->start), range_len(range));
		if (error) {
			mem_hotplug_done();
			goto err_kasan;
		}

		error = arch_add_memory(nid, range->start, range_len(range),
					params);
	}

	//成功添加PFN后，将range包含的返回纳入到ZONE_DEVICE管理范畴之内
	//这一步不一定会扩大ZONE_DEVICE的管理范围，因为ZONE_DEVICE内部可能会存在空洞区域
	if (!error) {
		struct zone *zone;

		zone = &NODE_DATA(nid)->node_zones[ZONE_DEVICE];
		move_pfn_range_to_zone(zone, PHYS_PFN(range->start),
				PHYS_PFN(range_len(range)), params->altmap,
				MIGRATE_MOVABLE, false);
	}

	mem_hotplug_done();
	if (error)
		goto err_add_memory;

	/*
	 * Initialization of the pages has been deferred until now in order
	 * to allow us to do the work while not holding the hotplug lock.
	 */
	//最后调用该函数，遍历这段range里面的所有PFN，初始化每个struct page对象（初始化基础信息，并且将refcount = 0）。这一步后每个device page就正式拥有了struct page省份
	//注意，每个struct page初始化完成后的refcount=0,后续调用分配函数zone_device_page_init()时才会增加refcount
	memmap_init_zone_device(&NODE_DATA(nid)->node_zones[ZONE_DEVICE],
				PHYS_PFN(range->start),
				PHYS_PFN(range_len(range)), pgmap);
	if (pgmap->type != MEMORY_DEVICE_PRIVATE &&
	    pgmap->type != MEMORY_DEVICE_COHERENT)
		percpu_ref_get_many(&pgmap->ref, pfn_len(pgmap, range_id));
	return 0;

err_add_memory:
	if (!is_private)
		kasan_remove_zero_shadow(__va(range->start), range_len(range));
err_kasan:
	pfnmap_untrack(PHYS_PFN(range->start), range_len(range));
err_pfn_remap:
	pgmap_array_delete(range);
	return error;
}


/*
 * Not device managed version of devm_memremap_pages, undone by
 * memunmap_pages().  Please use devm_memremap_pages if you have a struct
 * device available.
 */
void *memremap_pages(struct dev_pagemap *pgmap, int nid)
{
	struct mhp_params params = {
		.altmap = pgmap_altmap(pgmap),
		.pgmap = pgmap,
		.pgprot = PAGE_KERNEL,
	};
	const int nr_range = pgmap->nr_range;
	int error, i;

	if (WARN_ONCE(!nr_range, "nr_range must be specified\n"))
		return ERR_PTR(-EINVAL);
	if (WARN_ONCE(pgmap->vmemmap_shift > MAX_FOLIO_ORDER,
		      "requested folio size unsupported\n"))
		return ERR_PTR(-EINVAL);

	switch (pgmap->type) {									//条件验证
	case MEMORY_DEVICE_PRIVATE:
		if (!IS_ENABLED(CONFIG_DEVICE_PRIVATE)) {
			WARN(1, "Device private memory not supported\n");
			return ERR_PTR(-EINVAL);
		}
		if (!pgmap->ops || !pgmap->ops->migrate_to_ram) {
			WARN(1, "Missing migrate_to_ram method\n");
			return ERR_PTR(-EINVAL);
		}
		if (!pgmap->ops->page_free) {
			WARN(1, "Missing page_free method\n");
			return ERR_PTR(-EINVAL);
		}
		if (!pgmap->owner) {
			WARN(1, "Missing owner\n");
			return ERR_PTR(-EINVAL);
		}
		break;
	case MEMORY_DEVICE_COHERENT:
		if (!pgmap->ops->page_free) {
			WARN(1, "Missing page_free method\n");
			return ERR_PTR(-EINVAL);
		}
		if (!pgmap->owner) {
			WARN(1, "Missing owner\n");
			return ERR_PTR(-EINVAL);
		}
		break;
	case MEMORY_DEVICE_FS_DAX:
		params.pgprot = pgprot_decrypted(params.pgprot);
		break;
	case MEMORY_DEVICE_GENERIC:
		break;
	case MEMORY_DEVICE_PCI_P2PDMA:
		params.pgprot = pgprot_noncached(params.pgprot);
		break;
	default:
		WARN(1, "Invalid pgmap type %d\n", pgmap->type);
		break;
	}

	init_completion(&pgmap->done);															//初始化completion
	error = percpu_ref_init(&pgmap->ref, dev_pagemap_percpu_release, 0,	GFP_KERNEL);		//初始化ref引用计数
	if (error)
		return ERR_PTR(error);

	/*
	 * Clear the pgmap nr_range as it will be incremented for each
	 * successfully processed range. This communicates how many
	 * regions to unwind in the abort case.
	 */
	pgmap->nr_range = 0;
	error = 0;
	for (i = 0; i < nr_range; i++) {
		error = pagemap_range(pgmap, &params, i, nid);
		if (error)
			break;
		pgmap->nr_range++;
	}

	if (i < nr_range) {
		memunmap_pages(pgmap);
		pgmap->nr_range = nr_range;
		return ERR_PTR(error);
	}

	return __va(pgmap->ranges[0].start);
}
EXPORT_SYMBOL_GPL(memremap_pages);

/**
 * devm_memremap_pages - remap and provide memmap backing for the given resource
 * @dev: hosting device for @res
 * @pgmap: pointer to a struct dev_pagemap
 *
 * Notes:
 * 1/ At a minimum the range and type members of @pgmap must be initialized
 *    by the caller before passing it to this function
 *
 * 2/ The altmap field may optionally be initialized, in which case
 *    PGMAP_ALTMAP_VALID must be set in pgmap->flags.
 *
 * 3/ The ref field may optionally be provided, in which pgmap->ref must be
 *    'live' on entry and will be killed and reaped at
 *    devm_memremap_pages_release() time, or if this routine fails.
 *
 * 4/ range is expected to be a host memory range that could feasibly be
 *    treated as a "System RAM" range, i.e. not a device mmio range, but
 *    this is not enforced.
 */
void *devm_memremap_pages(struct device *dev, struct dev_pagemap *pgmap)
{
	int error;
	void *ret;

	ret = memremap_pages(pgmap, dev_to_node(dev));
	if (IS_ERR(ret))
		return ret;

	error = devm_add_action_or_reset(dev, devm_memremap_pages_release,
			pgmap);
	if (error)
		return ERR_PTR(error);
	return ret;
}
EXPORT_SYMBOL_GPL(devm_memremap_pages);

void devm_memunmap_pages(struct device *dev, struct dev_pagemap *pgmap)
{
	devm_release_action(dev, devm_memremap_pages_release, pgmap);
}
EXPORT_SYMBOL_GPL(devm_memunmap_pages);

/**
 * get_dev_pagemap() - take a new live reference on the dev_pagemap for @pfn
 * @pfn: page frame number to lookup page_map
 */
//该函数用于查找对应pgmap/struct dev_pagemap。（所有已注册的pgmap会被存放在全局变量pgmap_array中）
//---检测PFN是否在预先注册的dev_pagemap/pgmap区间内，是则返回该dev_pagemap
//---返回NULL，说明该PFN所在的pgmap没有被注册或者该pgmap处于被销毁流程中
//---其次，查到的pgmap不会直接返回，会先走percpu_ref_tryget_live_rcu去拿一个引用。如果没拿到引用，就说明该pgmap正在被销毁，就不会返回该pgmap，而是NULL
	//这保证了返回的pgmap是有效的
struct dev_pagemap *get_dev_pagemap(unsigned long pfn)
{
	struct dev_pagemap *pgmap;
	resource_size_t phys = PFN_PHYS(pfn);

	rcu_read_lock();					//这里用的rcu read锁，是因为read路径会出现在内存hotplug、memory failed等中，不能用重锁让它成为性能瓶颈
	pgmap = xa_load(&pgmap_array, PHYS_PFN(phys));
	if (pgmap && !percpu_ref_tryget_live_rcu(&pgmap->ref))		//这个pcp函数是检测pgmap是否进入销毁流程，如果正在执行销毁流程则返回NULL，
		pgmap = NULL;
	rcu_read_unlock();

	return pgmap;
}
EXPORT_SYMBOL_GPL(get_dev_pagemap);

void free_zone_device_folio(struct folio *folio)
{
	struct dev_pagemap *pgmap = folio->pgmap;

	if (WARN_ON_ONCE(!pgmap))
		return;

	mem_cgroup_uncharge(folio);

	/*
	 * Note: we don't expect anonymous compound pages yet. Once supported
	 * and we could PTE-map them similar to THP, we'd have to clear
	 * PG_anon_exclusive on all tail pages.
	 */
	if (folio_test_anon(folio)) {
		VM_BUG_ON_FOLIO(folio_test_large(folio), folio);
		__ClearPageAnonExclusive(folio_page(folio, 0));
	}

	/*
	 * When a device managed page is freed, the folio->mapping field
	 * may still contain a (stale) mapping value. For example, the
	 * lower bits of folio->mapping may still identify the folio as an
	 * anonymous folio. Ultimately, this entire field is just stale
	 * and wrong, and it will cause errors if not cleared.
	 *
	 * For other types of ZONE_DEVICE pages, migration is either
	 * handled differently or not done at all, so there is no need
	 * to clear folio->mapping.
	 *
	 * FS DAX pages clear the mapping when the folio->share count hits
	 * zero which indicating the page has been removed from the file
	 * system mapping.
	 */
	if (pgmap->type != MEMORY_DEVICE_FS_DAX &&
	    pgmap->type != MEMORY_DEVICE_GENERIC)
		folio->mapping = NULL;

	switch (pgmap->type) {
	case MEMORY_DEVICE_PRIVATE:
	case MEMORY_DEVICE_COHERENT:
		if (WARN_ON_ONCE(!pgmap->ops || !pgmap->ops->page_free))
			break;
		pgmap->ops->page_free(folio_page(folio, 0));
		put_dev_pagemap(pgmap);
		break;

	case MEMORY_DEVICE_GENERIC:
		/*
		 * Reset the refcount to 1 to prepare for handing out the page
		 * again.
		 */
		folio_set_count(folio, 1);
		break;

	case MEMORY_DEVICE_FS_DAX:
		wake_up_var(&folio->page);
		break;

	case MEMORY_DEVICE_PCI_P2PDMA:
		if (WARN_ON_ONCE(!pgmap->ops || !pgmap->ops->page_free))
			break;
		pgmap->ops->page_free(folio_page(folio, 0));
		break;
	}
}

void zone_device_page_init(struct page *page)
{
	/*
	 * Drivers shouldn't be allocating pages after calling
	 * memunmap_pages().
	 */
	WARN_ON_ONCE(!percpu_ref_tryget_live(&page_pgmap(page)->ref));		//folio->pgmap->ref
	set_page_count(page, 1);
	lock_page(page);
}
EXPORT_SYMBOL_GPL(zone_device_page_init);
