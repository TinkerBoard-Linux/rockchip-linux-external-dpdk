/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Fuzhou Rockchip Electronics Co., Ltd
 */

#ifndef __STMMAC_ETHDEV_H__
#define __STMMAC_ETHDEV_H__

#include "descs.h"
#include <rte_ethdev.h>

#define STMMAC_RX_COE_NONE	0
#define STMMAC_RX_COE_TYPE1	1
#define STMMAC_RX_COE_TYPE2	2

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if 0
#define stmmac_do_void_callback(__priv, __module, __cname,  __arg0, __args...) \
({ \
	int __result = -EINVAL; \
	if ((__priv)->hw->__module && (__priv)->hw->__module->__cname) { \
		(__priv)->hw->__module->__cname((__arg0), ##__args); \
		__result = 0; \
	} \
	__result; \
})
#define stmmac_do_callback(__priv, __module, __cname,  __arg0, __args...) \
({ \
	int __result = -EINVAL; \
	if ((__priv)->hw->__module && (__priv)->hw->__module->__cname) \
		__result = (__priv)->hw->__module->__cname((__arg0), ##__args); \
	__result; \
})

struct stmmac_extra_stats;
struct stmmac_safety_stats;
struct dma_desc;
struct dma_extended_desc;
struct dma_edesc;

/* Descriptors helpers */
struct stmmac_desc_ops {
	/* DMA RX descriptor ring initialization */
	void (*init_rx_desc)(struct dma_desc *p, int disable_rx_ic, int mode,
			int end, int bfsize);
	/* DMA TX descriptor ring initialization */
	void (*init_tx_desc)(struct dma_desc *p, int mode, int end);
	/* Invoked by the xmit function to prepare the tx descriptor */
	void (*prepare_tx_desc)(struct dma_desc *p, int is_fs, int len,
			bool csum_flag, int mode, bool tx_own, bool ls,
			unsigned int tot_pkt_len);
	void (*prepare_tso_tx_desc)(struct dma_desc *p, int is_fs, int len1,
			int len2, bool tx_own, bool ls, unsigned int tcphdrlen,
			unsigned int tcppayloadlen);
	/* Set/get the owner of the descriptor */
	void (*set_tx_owner)(struct dma_desc *p);
	int (*get_tx_owner)(struct dma_desc *p);
	/* Clean the tx descriptor as soon as the tx irq is received */
	void (*release_tx_desc)(struct dma_desc *p, int mode);
	/* Clear interrupt on tx frame completion. When this bit is
	 * set an interrupt happens as soon as the frame is transmitted */
	void (*set_tx_ic)(struct dma_desc *p);
	/* Last tx segment reports the transmit status */
	int (*get_tx_ls)(struct dma_desc *p);
	/* Return the transmit status looking at the TDES1 */
	int (*tx_status)(void *data, struct stmmac_extra_stats *x,
			struct dma_desc *p, void *ioaddr);
	/* Get the buffer size from the descriptor */
	int (*get_tx_len)(struct dma_desc *p);
	/* Handle extra events on specific interrupts hw dependent */
	void (*set_rx_owner)(struct dma_desc *p, int disable_rx_ic);
	/* Get the receive frame size */
	int (*get_rx_frame_len)(struct dma_desc *p, int rx_coe_type);
	/* Return the reception status looking at the RDES1 */
	int (*rx_status)(struct rte_eth_stats *x,
				       struct dma_desc *p);
	void (*rx_extended_status)(void *data, struct stmmac_extra_stats *x,
			struct dma_extended_desc *p);
	/* Set tx timestamp enable bit */
	void (*enable_tx_timestamp) (struct dma_desc *p);
	/* get tx timestamp status */
	int (*get_tx_timestamp_status) (struct dma_desc *p);
	/* get timestamp value */
	void (*get_timestamp)(void *desc, uint32_t ats, uint64_t *ts);
	/* get rx timestamp status */
	int (*get_rx_timestamp_status)(void *desc, void *next_desc, uint32_t ats);
	/* Display ring */
	void (*display_ring)(void *head, unsigned int size, bool rx,
			     dma_addr_t dma_rx_phy, unsigned int desc_size);
	/* set MSS via context descriptor */
	void (*set_mss)(struct dma_desc *p, unsigned int mss);
	/* get descriptor skbuff address */
	void (*get_addr)(struct dma_desc *p, unsigned int *addr);
	/* set descriptor skbuff address */
	void (*set_addr)(struct dma_desc *p, dma_addr_t addr);
	/* clear descriptor */
	void (*clear)(struct dma_desc *p);
	void (*get_rx_header_len)(struct dma_desc *p, unsigned int *len);
	void (*set_sec_addr)(struct dma_desc *p, dma_addr_t addr, bool buf2_valid);
	void (*set_sarc)(struct dma_desc *p, uint32_t sarc_type);
	void (*set_vlan_tag)(struct dma_desc *p, uint16_t tag, uint16_t inner_tag,
			     uint32_t inner_type);
	void (*set_vlan)(struct dma_desc *p, uint32_t type);
	void (*set_tbs)(struct dma_edesc *p, uint32_t sec, uint32_t nsec);
};

#define stmmac_init_rx_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, init_rx_desc, __args)
#define stmmac_init_tx_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, init_tx_desc, __args)
#define stmmac_prepare_tx_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, prepare_tx_desc, __args)
#define stmmac_prepare_tso_tx_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, prepare_tso_tx_desc, __args)
#define stmmac_set_tx_owner(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_tx_owner, __args)
#define stmmac_get_tx_owner(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_tx_owner, __args)
#define stmmac_release_tx_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, release_tx_desc, __args)
#define stmmac_set_tx_ic(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_tx_ic, __args)
#define stmmac_get_tx_ls(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_tx_ls, __args)
#define stmmac_tx_status(__priv, __args...) \
	stmmac_do_callback(__priv, desc, tx_status, __args)
#define stmmac_get_tx_len(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_tx_len, __args)
#define stmmac_set_rx_owner(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_rx_owner, __args)
#define stmmac_get_rx_frame_len(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_rx_frame_len, __args)
#define stmmac_rx_status(__priv, __args...) \
	stmmac_do_callback(__priv, desc, rx_status, __args)
#define stmmac_rx_extended_status(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, rx_extended_status, __args)
#define stmmac_enable_tx_timestamp(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, enable_tx_timestamp, __args)
#define stmmac_get_tx_timestamp_status(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_tx_timestamp_status, __args)
#define stmmac_get_timestamp(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, get_timestamp, __args)
#define stmmac_get_rx_timestamp_status(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_rx_timestamp_status, __args)
#define stmmac_display_ring(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, display_ring, __args)
#define stmmac_set_mss(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_mss, __args)
#define stmmac_get_desc_addr(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, get_addr, __args)
#define stmmac_set_desc_addr(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_addr, __args)
#define stmmac_clear_desc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, clear, __args)
#define stmmac_get_rx_hash(__priv, __args...) \
	stmmac_do_callback(__priv, desc, get_rx_hash, __args)
#define stmmac_get_rx_header_len(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, get_rx_header_len, __args)
#define stmmac_set_desc_sec_addr(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_sec_addr, __args)
#define stmmac_set_desc_sarc(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_sarc, __args)
#define stmmac_set_desc_vlan_tag(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_vlan_tag, __args)
#define stmmac_set_desc_vlan(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_vlan, __args)
#define stmmac_set_desc_tbs(__priv, __args...) \
	stmmac_do_void_callback(__priv, desc, set_tbs, __args)

struct stmmac_dma_cfg;
struct dma_features;

#define stmmac_reset(__priv, __args...) \
	stmmac_do_callback(__priv, dma, reset, __args)
#define stmmac_dma_init(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, init, __args)
#define stmmac_init_chan(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, init_chan, __args)
#define stmmac_init_rx_chan(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, init_rx_chan, __args)
#define stmmac_init_tx_chan(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, init_tx_chan, __args)
#define stmmac_axi(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, axi, __args)
#define stmmac_dump_dma_regs(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, dump_regs, __args)
#define stmmac_dma_rx_mode(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, dma_rx_mode, __args)
#define stmmac_dma_tx_mode(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, dma_tx_mode, __args)
#define stmmac_dma_diagnostic_fr(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, dma_diagnostic_fr, __args)
#define stmmac_enable_dma_transmission(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, enable_dma_transmission, __args)
#define stmmac_enable_dma_irq(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, enable_dma_irq, __args)
#define stmmac_disable_dma_irq(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, disable_dma_irq, __args)
#define stmmac_start_tx(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, start_tx, __args)
#define stmmac_stop_tx(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, stop_tx, __args)
#define stmmac_start_rx(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, start_rx, __args)
#define stmmac_stop_rx(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, stop_rx, __args)
#define stmmac_dma_interrupt_status(__priv, __args...) \
	stmmac_do_callback(__priv, dma, dma_interrupt, __args)
#define stmmac_get_hw_feature(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, get_hw_feature, __args)
#define stmmac_rx_watchdog(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, rx_watchdog, __args)
#define stmmac_set_tx_ring_len(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, set_tx_ring_len, __args)
#define stmmac_set_rx_ring_len(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, set_rx_ring_len, __args)
#define stmmac_set_rx_tail_ptr(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, set_rx_tail_ptr, __args)
#define stmmac_set_tx_tail_ptr(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, set_tx_tail_ptr, __args)
#define stmmac_enable_tso(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, enable_tso, __args)
#define stmmac_dma_qmode(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, qmode, __args)
#define stmmac_set_dma_bfsize(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, set_bfsize, __args)
#define stmmac_enable_sph(__priv, __args...) \
	stmmac_do_void_callback(__priv, dma, enable_sph, __args)
#define stmmac_enable_tbs(__priv, __args...) \
	stmmac_do_callback(__priv, dma, enable_tbs, __args)

struct mac_device_info;
struct net_device;
struct rgmii_adv;
struct stmmac_safety_stats;
struct stmmac_tc_entry;
struct stmmac_pps_cfg;
struct stmmac_rss;
struct stmmac_est;

#define stmmac_core_init(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, core_init, __args)
#define stmmac_mac_set(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_mac, __args)
#define stmmac_rx_ipc(__priv, __args...) \
	stmmac_do_callback(__priv, mac, rx_ipc, __args)
#define stmmac_rx_queue_enable(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, rx_queue_enable, __args)
#define stmmac_rx_queue_prio(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, rx_queue_prio, __args)
#define stmmac_tx_queue_prio(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, tx_queue_prio, __args)
#define stmmac_rx_queue_routing(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, rx_queue_routing, __args)
#define stmmac_prog_mtl_rx_algorithms(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, prog_mtl_rx_algorithms, __args)
#define stmmac_prog_mtl_tx_algorithms(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, prog_mtl_tx_algorithms, __args)
#define stmmac_set_mtl_tx_queue_weight(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_mtl_tx_queue_weight, __args)
#define stmmac_map_mtl_to_dma(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, map_mtl_to_dma, __args)
#define stmmac_config_cbs(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, config_cbs, __args)
#define stmmac_dump_mac_regs(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, dump_regs, __args)
#define stmmac_host_irq_status(__priv, __args...) \
	stmmac_do_callback(__priv, mac, host_irq_status, __args)
#define stmmac_host_mtl_irq_status(__priv, __args...) \
	stmmac_do_callback(__priv, mac, host_mtl_irq_status, __args)
#define stmmac_set_filter(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_filter, __args)
#define stmmac_flow_ctrl(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, flow_ctrl, __args)
#define stmmac_pmt(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, pmt, __args)
#define stmmac_set_umac_addr(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_umac_addr, __args)
#define stmmac_get_umac_addr(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, get_umac_addr, __args)
#define stmmac_set_eee_mode(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_eee_mode, __args)
#define stmmac_reset_eee_mode(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, reset_eee_mode, __args)
#define stmmac_set_eee_timer(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_eee_timer, __args)
#define stmmac_set_eee_pls(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_eee_pls, __args)
#define stmmac_mac_debug(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, debug, __args)
#define stmmac_pcs_ctrl_ane(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, pcs_ctrl_ane, __args)
#define stmmac_pcs_rane(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, pcs_rane, __args)
#define stmmac_pcs_get_adv_lp(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, pcs_get_adv_lp, __args)
#define stmmac_safety_feat_config(__priv, __args...) \
	stmmac_do_callback(__priv, mac, safety_feat_config, __args)
#define stmmac_safety_feat_irq_status(__priv, __args...) \
	stmmac_do_callback(__priv, mac, safety_feat_irq_status, __args)
#define stmmac_safety_feat_dump(__priv, __args...) \
	stmmac_do_callback(__priv, mac, safety_feat_dump, __args)
#define stmmac_rxp_config(__priv, __args...) \
	stmmac_do_callback(__priv, mac, rxp_config, __args)
#define stmmac_flex_pps_config(__priv, __args...) \
	stmmac_do_callback(__priv, mac, flex_pps_config, __args)
#define stmmac_set_mac_loopback(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_mac_loopback, __args)
#define stmmac_rss_configure(__priv, __args...) \
	stmmac_do_callback(__priv, mac, rss_configure, __args)
#define stmmac_update_vlan_hash(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, update_vlan_hash, __args)
#define stmmac_enable_vlan(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, enable_vlan, __args)
#define stmmac_add_hw_vlan_rx_fltr(__priv, __args...) \
	stmmac_do_callback(__priv, mac, add_hw_vlan_rx_fltr, __args)
#define stmmac_del_hw_vlan_rx_fltr(__priv, __args...) \
	stmmac_do_callback(__priv, mac, del_hw_vlan_rx_fltr, __args)
#define stmmac_restore_hw_vlan_rx_fltr(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, restore_hw_vlan_rx_fltr, __args)
#define stmmac_get_mac_tx_timestamp(__priv, __args...) \
	stmmac_do_callback(__priv, mac, get_mac_tx_timestamp, __args)
#define stmmac_sarc_configure(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, sarc_configure, __args)
#define stmmac_config_l3_filter(__priv, __args...) \
	stmmac_do_callback(__priv, mac, config_l3_filter, __args)
#define stmmac_config_l4_filter(__priv, __args...) \
	stmmac_do_callback(__priv, mac, config_l4_filter, __args)
#define stmmac_set_arp_offload(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, set_arp_offload, __args)
#define stmmac_est_configure(__priv, __args...) \
	stmmac_do_callback(__priv, mac, est_configure, __args)
#define stmmac_fpe_configure(__priv, __args...) \
	stmmac_do_void_callback(__priv, mac, fpe_configure, __args)

/* Specific DMA helpers */
struct stmmac_dma_ops {
	/* DMA core initialization */
	int (*reset)(void  *ioaddr);
	void (*init)(void  *ioaddr, struct stmmac_dma_cfg *dma_cfg,
		     int atds);
	void (*init_chan)(void  *ioaddr,
			  struct stmmac_dma_cfg *dma_cfg, uint32_t chan);
	void (*init_rx_chan)(void  *ioaddr,
			     struct stmmac_dma_cfg *dma_cfg,
			     dma_addr_t phy, uint32_t chan);
	void (*init_tx_chan)(void  *ioaddr,
			     struct stmmac_dma_cfg *dma_cfg,
			     dma_addr_t phy, uint32_t chan);
	/* Dump DMA registers */
	void (*dump_regs)(void  *ioaddr, uint32_t *reg_space);
	void (*dma_rx_mode)(void  *ioaddr, int mode, uint32_t channel,
			    int fifosz, uint8_t qmode);
	void (*dma_tx_mode)(void  *ioaddr, int mode, uint32_t channel,
			    int fifosz, uint8_t qmode);
	/* To track extra statistic (if supported) */
	void (*dma_diagnostic_fr) (void *data, struct stmmac_extra_stats *x,
				   void  *ioaddr);
	void (*enable_dma_transmission) (void  *ioaddr);
	void (*enable_dma_irq)(void  *ioaddr, uint32_t chan,
			       bool rx, bool tx);
	void (*disable_dma_irq)(void  *ioaddr, uint32_t chan,
				bool rx, bool tx);
	void (*start_tx)(void  *ioaddr, uint32_t chan);
	void (*stop_tx)(void  *ioaddr, uint32_t chan);
	void (*start_rx)(void  *ioaddr, uint32_t chan);
	void (*stop_rx)(void  *ioaddr, uint32_t chan);
	int (*dma_interrupt) (void  *ioaddr,
			      struct stmmac_extra_stats *x, uint32_t chan);
	/* If supported then get the optional core features */
	void (*get_hw_feature)(void  *ioaddr,
			       struct dma_features *dma_cap);
	/* Program the HW RX Watchdog */
	void (*rx_watchdog)(void  *ioaddr, uint32_t riwt, uint32_t number_chan);
	void (*set_tx_ring_len)(void  *ioaddr, uint32_t len, uint32_t chan);
	void (*set_rx_ring_len)(void  *ioaddr, uint32_t len, uint32_t chan);
	void (*set_rx_tail_ptr)(void  *ioaddr, uint32_t tail_ptr, uint32_t chan);
	void (*set_tx_tail_ptr)(void  *ioaddr, uint32_t tail_ptr, uint32_t chan);
	void (*enable_tso)(void  *ioaddr, bool en, uint32_t chan);
	void (*qmode)(void  *ioaddr, uint32_t channel, uint8_t qmode);
	void (*set_bfsize)(void  *ioaddr, int bfsize, uint32_t chan);
	void (*enable_sph)(void  *ioaddr, bool en, uint32_t chan);
	int (*enable_tbs)(void  *ioaddr, bool en, uint32_t chan);
};

struct stmmac_regs_off {
	uint32_t ptp_off;
	uint32_t mmc_off;
};

extern const struct stmmac_ops dwmac100_ops;
extern const struct stmmac_dma_ops dwmac100_dma_ops;
extern const struct stmmac_ops dwmac1000_ops;
extern const struct stmmac_dma_ops dwmac1000_dma_ops;
extern const struct stmmac_ops dwmac4_ops;
extern const struct stmmac_dma_ops dwmac4_dma_ops;
extern const struct stmmac_ops dwmac410_ops;
extern const struct stmmac_dma_ops dwmac410_dma_ops;
extern const struct stmmac_ops dwmac510_ops;

#define GMAC_VERSION		0x00000020	/* GMAC CORE Version */
#define GMAC4_VERSION		0x00000110	/* GMAC4+ CORE Version */

#define stmmac_mode_init(__priv, __args...) \
	stmmac_do_void_callback(__priv, mode, init, __args)
#define stmmac_is_jumbo_frm(__priv, __args...) \
	stmmac_do_callback(__priv, mode, is_jumbo_frm, __args)
#define stmmac_jumbo_frm(__priv, __args...) \
	stmmac_do_callback(__priv, mode, jumbo_frm, __args)
#define stmmac_set_16kib_bfsize(__priv, __args...) \
	stmmac_do_callback(__priv, mode, set_16kib_bfsize, __args)
#define stmmac_init_desc3(__priv, __args...) \
	stmmac_do_void_callback(__priv, mode, init_desc3, __args)
#define stmmac_refill_desc3(__priv, __args...) \
	stmmac_do_void_callback(__priv, mode, refill_desc3, __args)
#define stmmac_clean_desc3(__priv, __args...) \
	stmmac_do_void_callback(__priv, mode, clean_desc3, __args)
#endif

#define BD_LEN			49152
#define STMMAC_TX_FR_SIZE	2048
#define ETH_HLEN		RTE_ETHER_HDR_LEN

/* full duplex */
#define FULL_DUPLEX		0x00

#define PKT_MAX_BUF_SIZE	1984
#define OPT_FRAME_SIZE		(PKT_MAX_BUF_SIZE << 16)
#define STMMAC_MAX_RX_PKT_LEN	3000

#if defined(RTE_ARCH_ARM)
#if defined(RTE_ARCH_64)
#define dcbf(p) { asm volatile("dc cvac, %0" : : "r"(p) : "memory"); }
#define dcbf_64(p) dcbf(p)
#define dcivac(p) { asm volatile("dc civac, %0" : : "r"(p) : "memory"); }
#define dcivac_64(p) dcivac(p)

#else /* RTE_ARCH_32 */
#define dcbf(p) RTE_SET_USED(p)
#define dcbf_64(p) dcbf(p)
#define dcivac(p)	RTE_SET_USED(p)
#endif

#else
#define dcbf(p) RTE_SET_USED(p)
#define dcbf_64(p) dcbf(p)
#define dcivac(p)	RTE_SET_USED(p)
#endif

#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")
#define wmb()		dsb(st)
#define wsb()		dsb(sy)
#define isb()		asm volatile("isb" : : : "memory")
#define barrier()	asm volatile ("" : : : "memory");

#if 0
static inline struct
bufdesc *stmmac_get_nextdesc(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return (bdp >= bd->last) ? bd->base
		: (struct bufdesc *)(((uintptr_t)bdp) + bd->d_size);
}

static inline int
fls64(unsigned long word)
{
	return (64 - __builtin_clzl(word)) - 1;
}

static inline struct
bufdesc *stmmac_get_prevdesc(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return (bdp <= bd->base) ? bd->last
		: (struct bufdesc *)(((uintptr_t)bdp) - bd->d_size);
}

static inline int
stmmac_get_bd_index(struct bufdesc *bdp, struct bufdesc_prop *bd)
{
	return ((const char *)bdp - (const char *)bd->base) >> bd->d_size_log2;
}
#endif

uint16_t stmmac_recv_pkts(void *rxq1, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t stmmac_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);

#endif /*__STMMAC_ETHDEV_H__*/
