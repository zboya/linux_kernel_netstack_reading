/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/bitmap.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 */

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

enum {
	NEIGH_VAR_MCAST_PROBES,
	NEIGH_VAR_UCAST_PROBES,
	NEIGH_VAR_APP_PROBES,
	NEIGH_VAR_MCAST_REPROBES,
	NEIGH_VAR_RETRANS_TIME,
	NEIGH_VAR_BASE_REACHABLE_TIME,
	NEIGH_VAR_DELAY_PROBE_TIME,
	NEIGH_VAR_GC_STALETIME,
	NEIGH_VAR_QUEUE_LEN_BYTES,
	NEIGH_VAR_PROXY_QLEN,
	NEIGH_VAR_ANYCAST_DELAY,
	NEIGH_VAR_PROXY_DELAY,
	NEIGH_VAR_LOCKTIME,
#define NEIGH_VAR_DATA_MAX (NEIGH_VAR_LOCKTIME + 1)
	/* Following are used as a second way to access one of the above */
	NEIGH_VAR_QUEUE_LEN, /* same data as NEIGH_VAR_QUEUE_LEN_BYTES */
	NEIGH_VAR_RETRANS_TIME_MS, /* same data as NEIGH_VAR_RETRANS_TIME */
	NEIGH_VAR_BASE_REACHABLE_TIME_MS, /* same data as NEIGH_VAR_BASE_REACHABLE_TIME */
	/* Following are used by "default" only */
	NEIGH_VAR_GC_INTERVAL,
	NEIGH_VAR_GC_THRESH1,
	NEIGH_VAR_GC_THRESH2,
	NEIGH_VAR_GC_THRESH3,
	NEIGH_VAR_MAX
};

/*
 * 邻居协议参数配置块，用于存储可调节的邻居协议
 * 参数，如重传超时时间、proxy_queue队列长度等。一个
 * 邻居协议对应一个参数配置块，而每一个网络设备
 * 的IPv4的配置块中也存在一个存放默认值的邻居配置
 * 块。
 */
struct neigh_parms {
	possible_net_t net;
	/*
	 * 指向该neigh_parms实例所对应的网络设备，
	 * 在通过neigh_parms_alloc()创建neigh_parms实例时
	 * 设置。
	 */
	struct net_device *dev;
	/*
	 * 通过list将属于同一个协议族的所有neigh_parms实例
	 * 链接在一起，每个neigh_table实例都有各自的neigh_parms
	 * 队列。
	 */
	struct list_head list;
	/*
	 * 提供给那些仍在使用老式接口设备的初始化和销毁
	 * 接口。net_device结构中也有一个neigh_setup成员函数指针，
	 * 不要与之混淆。
	 */
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	/*
	 * 指向该neigh_parms实例所属的邻居表。
	 */
	struct neigh_table *tbl;
	/*
	 * 邻居表的sysctl表，对ARP是在ARP模块初始化函数
	 * arp_init()中对其初始化的，这样用户可以通过
	 * proc文件系统来读写邻居表的参数。
	 */
	void	*sysctl_table;

	/*
	 * 该字段值如果为1，则该邻居参数实例正在被删除，
	 * 不能再使用，也不能再创建对应网络设备的邻居项。
	 * 例如，在网络设备禁用时调用neigh_parms_release()设置。
	 */
	int dead;
	/*
	 * 引用计数。
	 */
	refcount_t refcnt;
	/*
	 * 为控制同步访问而设置的参数。
	 */
	struct rcu_head rcu_head;

	int	reachable_time;
	int	data[NEIGH_VAR_DATA_MAX];
	DECLARE_BITMAP(data_state, NEIGH_VAR_DATA_MAX);
};

static inline void neigh_var_set(struct neigh_parms *p, int index, int val)
{
	set_bit(index, p->data_state);
	p->data[index] = val;
}

#define NEIGH_VAR(p, attr) ((p)->data[NEIGH_VAR_ ## attr])

/* In ndo_neigh_setup, NEIGH_VAR_INIT should be used.
 * In other cases, NEIGH_VAR_SET should be used.
 */
#define NEIGH_VAR_INIT(p, attr, val) (NEIGH_VAR(p, attr) = val)
#define NEIGH_VAR_SET(p, attr, val) neigh_var_set(p, NEIGH_VAR_ ## attr, val)

static inline void neigh_parms_data_state_setall(struct neigh_parms *p)
{
	bitmap_fill(p->data_state, NEIGH_VAR_DATA_MAX);
}

static inline void neigh_parms_data_state_cleanall(struct neigh_parms *p)
{
	bitmap_zero(p->data_state, NEIGH_VAR_DATA_MAX);
}

struct neigh_statistics {
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* number of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */

	unsigned long unres_discards;	/* number of unresolved drops */
	unsigned long table_fulls;      /* times even gc couldn't help */
};

#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)

// 邻居的结构体
struct neighbour {
	struct neighbour __rcu	*next;
	struct neigh_table	*tbl;
	struct neigh_parms	*parms;
	unsigned long		confirmed;
	unsigned long		updated;
	rwlock_t		lock;
	refcount_t		refcnt;
	struct sk_buff_head	arp_queue;
	unsigned int		arp_queue_len_bytes;
	struct timer_list	timer;
	unsigned long		used;
	atomic_t		probes;
	__u8			flags;
	__u8			nud_state;
	__u8			type;
	__u8			dead;
	seqlock_t		ha_lock;
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	struct hh_cache		hh;
	// Show Uses: (18)
	// linux/include/net/neighbour.h (1)
	// neigh_output (1 r)
	// linux/net/atm/clip.c (1)
	// clip_constructor (1 w)
	// linux/net/bridge/br_netfilter_hooks.c (1)
	// br_nf_pre_routing_finish_bridge (1 r)
	// linux/net/core/neighbour.c (6)
	// neigh_flush_dev (1 w)
	// neigh_alloc (1 w)
	// neigh_suspect (1 w)
	// neigh_connect (1 w)
	// neigh_update (1 r)
	// neigh_xmit (1 r)
	// linux/net/decnet/dn_neigh.c (2)
	// dn_neigh_construct (1 w)
	// dn_neigh_output_packet (1 r)
	// linux/net/ipv4/arp.c (3)
	// arp_constructor (3 w)
	// linux/net/ipv6/ndisc.c (3)
	// ndisc_constructor (3 w)
	// linux/drivers/s390/net/qeth_l3_main.c (1)
	// qeth_l3_neigh_setup_noarp (1 w)
	int			(*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops	*ops;
	struct rcu_head		rcu;
	struct net_device	*dev;
	u8			primary_key[0];
} __randomize_layout;

/*
 * neigh_ops结构实际上是一个函数指针表，包含了一组
 * 函数指针，这些函数在一个neighbour实例的整个生命
 * 周期内会被使用到，由此实现了三层和二层的
 * dev_queue_xmit()之间的转接。
 */
struct neigh_ops {
	/*
	 * 标识所属的地址族，比如ARP为AF_INET等。
	 */
	int			family;
	/*
	 * 发送请求报文函数。在发送第一个报文时，需要
	 * 新的邻居项，发送报文被缓存到arp_queue队列中，
	 * 然后会调用solicit()发送请求报文。
	 */
	void			(*solicit)(struct neighbour *, struct sk_buff *);
	/*
	 * 当邻居项缓存着未发送的报文，而该邻居项又不可达时，
	 * 被调用来向三层报告错误的函数。ARP中为arp_error_report()，
	 * 最终会给报文发送方发送一个主机不可达的ICMP差错报文。
	 */
	void			(*error_report)(struct neighbour *, struct sk_buff *);
	/*
	 * 最通用的输出函数，可用于所有情况。此输出函数实现了
	 * 完整的输出过程，因此存在较多的校验与操作，以确保
	 * 报文的输出，因此该函数相对较消耗资源。此外，不要
	 * 将neigh_ops->output()与neighbour->output()混淆。
	 */
	int			(*output)(struct neighbour *, struct sk_buff *);
	/*
	 * 在确定邻居可达时，即状态为NUD_CONNECTED时使用的输出函数。
	 * 由于所有输出所需要的信息都已具备，因此该函数只是简单
	 * 地添加二层首部，也因此比output()快得多。
	 */
	int			(*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry	*next;
	possible_net_t		net;
	struct net_device	*dev;
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */

#define NEIGH_NUM_HASH_RND	4

struct neigh_hash_table {
	struct neighbour __rcu	**hash_buckets;
	unsigned int		hash_shift;
	__u32			hash_rnd[NEIGH_NUM_HASH_RND];
	struct rcu_head		rcu;
};

// 邻居表，在ipv4中就是arp表
struct neigh_table {
	int			family;
	unsigned int		entry_size;
	unsigned int		key_len;
	__be16			protocol;
	__u32			(*hash)(const void *pkey,
					const struct net_device *dev,
					__u32 *hash_rnd);
	bool			(*key_eq)(const struct neighbour *, const void *pkey);
	int			(*constructor)(struct neighbour *);
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id;
	struct neigh_parms	parms;
	struct list_head	parms_list;
	int			gc_interval;
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	unsigned long		last_flush;
	struct delayed_work	gc_work;
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue;
	atomic_t		entries;
	rwlock_t		lock;
	unsigned long		last_rand;
	struct neigh_statistics	__percpu *stats;
	struct neigh_hash_table __rcu *nht;
	struct pneigh_entry	**phash_buckets;
};

enum {
	NEIGH_ARP_TABLE = 0,
	NEIGH_ND_TABLE = 1,
	NEIGH_DN_TABLE = 2,
	NEIGH_NR_TABLES,
	NEIGH_LINK_TABLE = NEIGH_NR_TABLES /* Pseudo table for neigh_xmit */
};

static inline int neigh_parms_family(struct neigh_parms *p)
{
	return p->tbl->family;
}

#define NEIGH_PRIV_ALIGN	sizeof(long long)
#define NEIGH_ENTRY_SIZE(size)	ALIGN((size), NEIGH_PRIV_ALIGN)

static inline void *neighbour_priv(const struct neighbour *n)
{
	return (char *)n + n->tbl->entry_size;
}

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000


static inline bool neigh_key_eq16(const struct neighbour *n, const void *pkey)
{
	return *(const u16 *)n->primary_key == *(const u16 *)pkey;
}

static inline bool neigh_key_eq32(const struct neighbour *n, const void *pkey)
{
	return *(const u32 *)n->primary_key == *(const u32 *)pkey;
}

static inline bool neigh_key_eq128(const struct neighbour *n, const void *pkey)
{
	const u32 *n32 = (const u32 *)n->primary_key;
	const u32 *p32 = pkey;

	return ((n32[0] ^ p32[0]) | (n32[1] ^ p32[1]) |
		(n32[2] ^ p32[2]) | (n32[3] ^ p32[3])) == 0;
}

static inline struct neighbour *___neigh_lookup_noref(
	struct neigh_table *tbl,
	bool (*key_eq)(const struct neighbour *n, const void *pkey),
	__u32 (*hash)(const void *pkey,
		      const struct net_device *dev,
		      __u32 *hash_rnd),
	const void *pkey,
	struct net_device *dev)
{
	struct neigh_hash_table *nht = rcu_dereference_bh(tbl->nht);
	struct neighbour *n;
	u32 hash_val;

	hash_val = hash(pkey, dev, nht->hash_rnd) >> (32 - nht->hash_shift);
	for (n = rcu_dereference_bh(nht->hash_buckets[hash_val]);
	     n != NULL;
	     n = rcu_dereference_bh(n->next)) {
		if (n->dev == dev && key_eq(n, pkey))
			return n;
	}

	return NULL;
}

static inline struct neighbour *__neigh_lookup_noref(struct neigh_table *tbl,
						     const void *pkey,
						     struct net_device *dev)
{
	return ___neigh_lookup_noref(tbl, tbl->key_eq, tbl->hash, pkey, dev);
}

void neigh_table_init(int index, struct neigh_table *tbl);
int neigh_table_clear(int index, struct neigh_table *tbl);
struct neighbour *neigh_lookup(struct neigh_table *tbl, const void *pkey,
			       struct net_device *dev);
struct neighbour *neigh_lookup_nodev(struct neigh_table *tbl, struct net *net,
				     const void *pkey);
struct neighbour *__neigh_create(struct neigh_table *tbl, const void *pkey,
				 struct net_device *dev, bool want_ref);
static inline struct neighbour *neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev)
{
	return __neigh_create(tbl, pkey, dev, true);
}
void neigh_destroy(struct neighbour *neigh);
int __neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
int neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, u32 flags,
		 u32 nlmsg_pid);
void __neigh_set_probe_once(struct neighbour *neigh);
bool neigh_remove_one(struct neighbour *ndel, struct neigh_table *tbl);
void neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
int neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
int neigh_resolve_output(struct neighbour *neigh, struct sk_buff *skb);
int neigh_connected_output(struct neighbour *neigh, struct sk_buff *skb);
int neigh_direct_output(struct neighbour *neigh, struct sk_buff *skb);
struct neighbour *neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

struct neigh_parms *neigh_parms_alloc(struct net_device *dev,
				      struct neigh_table *tbl);
void neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net *neigh_parms_net(const struct neigh_parms *parms)
{
	return read_pnet(&parms->net);
}

unsigned long neigh_rand_reach_time(unsigned long base);

void pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
		    struct sk_buff *skb);
struct pneigh_entry *pneigh_lookup(struct neigh_table *tbl, struct net *net,
				   const void *key, struct net_device *dev,
				   int creat);
struct pneigh_entry *__pneigh_lookup(struct neigh_table *tbl, struct net *net,
				     const void *key, struct net_device *dev);
int pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key,
		  struct net_device *dev);

static inline struct net *pneigh_net(const struct pneigh_entry *pneigh)
{
	return read_pnet(&pneigh->net);
}

void neigh_app_ns(struct neighbour *n);
void neigh_for_each(struct neigh_table *tbl,
		    void (*cb)(struct neighbour *, void *), void *cookie);
void __neigh_for_each_release(struct neigh_table *tbl,
			      int (*cb)(struct neighbour *));
int neigh_xmit(int fam, struct net_device *, const void *, struct sk_buff *);
void pneigh_for_each(struct neigh_table *tbl,
		     void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	struct neigh_hash_table *nht;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *,
		      unsigned int);
void *neigh_seq_next(struct seq_file *, void *, loff_t *);
void neigh_seq_stop(struct seq_file *, void *);

int neigh_proc_dointvec(struct ctl_table *ctl, int write,
			void __user *buffer, size_t *lenp, loff_t *ppos);
int neigh_proc_dointvec_jiffies(struct ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos);
int neigh_proc_dointvec_ms_jiffies(struct ctl_table *ctl, int write,
				   void __user *buffer,
				   size_t *lenp, loff_t *ppos);

int neigh_sysctl_register(struct net_device *dev, struct neigh_parms *p,
			  proc_handler *proc_handler);
void neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	refcount_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	refcount_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (refcount_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		refcount_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	refcount_inc(&(n)->refcnt)

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	unsigned long now = jiffies;
	
	if (neigh->used != now)
		neigh->used = now;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
static inline int neigh_hh_bridge(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq, hh_alen;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(ETH_HLEN);
		memcpy(skb->data - hh_alen, hh->hh_data, ETH_ALEN + hh_alen - ETH_HLEN);
	} while (read_seqretry(&hh->hh_lock, seq));
	return 0;
}
#endif

static inline int neigh_hh_output(const struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned int seq;
	unsigned int hh_len;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		if (likely(hh_len <= HH_DATA_MOD)) {
			/* this is inlined by gcc */
			memcpy(skb->data - HH_DATA_MOD, hh->hh_data, HH_DATA_MOD);
		} else {
			unsigned int hh_alen = HH_DATA_ALIGN(hh_len);

			memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		}
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return dev_queue_xmit(skb);
}

static inline int neigh_output(struct neighbour *n, struct sk_buff *skb)
{
	const struct hh_cache *hh = &n->hh;

	if ((n->nud_state & NUD_CONNECTED) && hh->hh_len)
		return neigh_hh_output(hh, skb);
	else
		return n->output(n, skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

static inline void neigh_ha_snapshot(char *dst, const struct neighbour *n,
				     const struct net_device *dev)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&n->ha_lock);
		memcpy(dst, n->ha, dev->addr_len);
	} while (read_seqretry(&n->ha_lock, seq));
}


#endif
