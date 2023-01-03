/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Fuzhou Rockchip Electronics Co., Ltd
 */

#include <ethdev_vdev.h>
#include <ethdev_driver.h>
#include <rte_io.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "stmmac_pmd_logs.h"
#include "stmmac_ethdev.h"
#include "stmmac_regs.h"
#include "common.h"
#include "stmmac_ptp.h"
#include "stmmac.h"
#include "hwif.h"

#define STMMAC_NAME_PMD                net_stmmac

/* FEC receive acceleration */
#define STMMAC_RACC_IPDIS		RTE_BIT32(1)
#define STMMAC_RACC_PRODIS		RTE_BIT32(2)
#define STMMAC_RACC_SHIFT16		RTE_BIT32(7)
#define STMMAC_RACC_OPTIONS		(STMMAC_RACC_IPDIS | \
					STMMAC_RACC_PRODIS)

#define STMMAC_PAUSE_FLAG_AUTONEG	0x1
#define STMMAC_PAUSE_FLAG_ENABLE	0x2

/* Pause frame field and FIFO threshold */
#define STMMAC_FCE			RTE_BIT32(5)
#define STMMAC_RSEM_V			0x84
#define STMMAC_RSFL_V			16
#define STMMAC_RAEM_V			0x8
#define STMMAC_RAFL_V			0x8
#define STMMAC_OPD_V			0xFFF0

/* Supported Rx offloads */
static uint64_t dev_rx_offloads_sup =
		RTE_ETH_RX_OFFLOAD_CHECKSUM |
		RTE_ETH_RX_OFFLOAD_VLAN;

static uint32_t
stmmac_get_id(struct stmmac_private *priv, uint32_t id_reg)
{
	uint32_t reg = rte_read32((uint8_t *)priv->ioaddr_v + id_reg);

	if (!reg) {
		STMMAC_PMD_ERR("Version ID not available\n");
		return 0x0;
	}

	STMMAC_PMD_INFO("User ID: 0x%x, Synopsys ID: 0x%x\n",
			(unsigned int)(reg & GENMASK(15, 8)) >> 8,
			(unsigned int)(reg & GENMASK(7, 0)));
	return reg & GENMASK(7, 0);
}

static const struct stmmac_hwif_entry {
	bool gmac;
	bool gmac4;
	uint32_t min_id;
	uint32_t dev_id;
	const struct stmmac_regs_off regs;
	const void *desc;
	const void *dma;
	const void *mac;
	const void *hwtimestamp;
	const void *mode;
	const void *tc;
	const void *mmc;
	int (*setup)(struct stmmac_private *priv);
	int (*quirks)(struct stmmac_private *priv);
} stmmac_hw[] = {
	{
		.gmac = false,
		.gmac4 = true,
		.min_id = DWMAC_CORE_4_10,
		.regs = {
			.ptp_off = PTP_GMAC4_OFFSET,
			.mmc_off = MMC_GMAC4_OFFSET,
		},
		.desc = &dwmac4_desc_ops,
		.dma = &dwmac410_dma_ops,
		.mac = &dwmac410_ops,
		.mode = &dwmac4_ring_mode_ops,
		.setup = dwmac4_setup,
	},
};

static int
stmmac_hwif_init(struct stmmac_private *priv)
{
	bool needs_gmac4;
	bool needs_gmac;
	const struct stmmac_hwif_entry *entry;
	struct mac_device_info *mac;
	bool needs_setup = true;
	uint32_t id;
	int i, ret;

	needs_gmac4 = priv->plat->has_gmac4;
	needs_gmac = priv->plat->has_gmac;

	if (needs_gmac) {
		id = stmmac_get_id(priv, GMAC_VERSION);
	} else if (needs_gmac4) {
		id = stmmac_get_id(priv, GMAC4_VERSION);
	} else {
		id = 0;
	}

	/* Save ID for later use */
	priv->synopsys_id = id;

	/* Lets assume some safe values first */
	priv->ptpaddr = (uint8_t *)priv->ioaddr_v +
		(needs_gmac4 ? PTP_GMAC4_OFFSET : PTP_GMAC3_X_OFFSET);
	priv->mmcaddr = (uint8_t *)priv->ioaddr_v +
		(needs_gmac4 ? MMC_GMAC4_OFFSET : MMC_GMAC3_X_OFFSET);

	mac = rte_zmalloc("mac_device_info", sizeof(*mac), 0);
	if (!mac)
		return -ENOMEM;

	/* Fallback to generic HW */
	for (i = ARRAY_SIZE(stmmac_hw) - 1; i >= 0; i--) {
		entry = &stmmac_hw[i];

		if (needs_gmac ^ entry->gmac)
			continue;
		if (needs_gmac4 ^ entry->gmac4)
			continue;
		/* Use synopsys_id var because some setups can override this */
		if (priv->synopsys_id < entry->min_id)
			continue;

		/* Only use generic HW helpers if needed */
		mac->desc = mac->desc ? : entry->desc;
		mac->dma = mac->dma ? : entry->dma;
		mac->mac = mac->mac ? : entry->mac;
		mac->ptp = mac->ptp ? : entry->hwtimestamp;
		mac->mode = mac->mode ? : entry->mode;
		mac->tc = mac->tc ? : entry->tc;
		mac->mmc = mac->mmc ? : entry->mmc;

		priv->hw = mac;
		priv->ptpaddr = (uint8_t *)priv->ioaddr_v + entry->regs.ptp_off;
		priv->mmcaddr = (uint8_t *)priv->ioaddr_v + entry->regs.mmc_off;

		/* Entry found */
		if (needs_setup) {
			ret = entry->setup(priv);
			if (ret)
				return ret;
		}

		return 0;
	}

	STMMAC_PMD_ERR("Failed to find HW IF (id=0x%x, gmac=%d/%d)\n",
			id, needs_gmac, needs_gmac4);
	return -EINVAL;
}

/**
 * stmmac_start_rx_dma - start RX DMA channel
 * @priv: driver private structure
 * @chan: RX channel index
 * Description:
 * This starts a RX DMA channel
 */
static void
stmmac_start_rx_dma(struct stmmac_private *priv, uint32_t chan)
{
	STMMAC_PMD_INFO("DMA RX processes started in channel %d\n", chan);
	stmmac_start_rx(priv, priv->ioaddr_v, chan);
}

/**
 * stmmac_start_tx_dma - start TX DMA channel
 * @priv: driver private structure
 * @chan: TX channel index
 * Description:
 * This starts a TX DMA channel
 */
static void
stmmac_start_tx_dma(struct stmmac_private *priv, uint32_t chan)
{
	STMMAC_PMD_INFO("DMA TX processes started in channel %d\n", chan);
	stmmac_start_tx(priv, priv->ioaddr_v, chan);
}

/**
 * stmmac_stop_rx_dma - stop RX DMA channel
 * @priv: driver private structure
 * @chan: RX channel index
 * Description:
 * This stops a RX DMA channel
 */
static void
stmmac_stop_rx_dma(struct stmmac_private *priv, uint32_t chan)
{
	STMMAC_PMD_INFO("DMA RX processes stopped in channel %d\n", chan);
	stmmac_stop_rx(priv, priv->ioaddr_v, chan);
}

/**
 * stmmac_stop_tx_dma - stop TX DMA channel
 * @priv: driver private structure
 * @chan: TX channel index
 * Description:
 * This stops a TX DMA channel
 */
static void
stmmac_stop_tx_dma(struct stmmac_private *priv, uint32_t chan)
{
	STMMAC_PMD_INFO("DMA TX processes stopped in channel %d\n", chan);
	stmmac_stop_tx(priv, priv->ioaddr_v, chan);
}

/**
 * stmmac_start_all_dma - start all RX and TX DMA channels
 * @priv: driver private structure
 * Description:
 * This starts all the RX and TX DMA channels
 */
static void
stmmac_start_all_dma(struct stmmac_private *priv)
{
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t chan = 0;

	for (chan = 0; chan < rx_channels_count; chan++)
		stmmac_start_rx_dma(priv, chan);

	for (chan = 0; chan < tx_channels_count; chan++)
		stmmac_start_tx_dma(priv, chan);
}

/**
 * stmmac_stop_all_dma - stop all RX and TX DMA channels
 * @priv: driver private structure
 * Description:
 * This stops the RX and TX DMA channels
 */
static void
stmmac_stop_all_dma(struct stmmac_private *priv)
{
	uint32_t rx_channels_count = priv->rx_queues_to_use;
	uint32_t tx_channels_count = priv->tx_queues_to_use;
	uint32_t chan = 0;

	for (chan = 0; chan < rx_channels_count; chan++)
		stmmac_stop_rx_dma(priv, chan);

	for (chan = 0; chan < tx_channels_count; chan++)
		stmmac_stop_tx_dma(priv, chan);
}

/*
 * This function is called to start or restart the STMMAC during a link
 * change, transmit timeout, or to reconfigure the STMMAC. The network
 * packet processing for this device must be stopped before this call.
 */
static int
stmmac_start(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;

	/* Start the ball rolling... */
	stmmac_start_all_dma(private);

	rte_delay_us(200);

	return 0;
}

static void
stmmac_free_buffers(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;
	unsigned int i, q;
	struct rte_mbuf *mbuf;
	struct stmmac_rx_queue *rxq;
	struct stmmac_tx_queue *txq;

	for (q = 0; q < dev->data->nb_rx_queues; q++) {
		rxq = private->rx_queues[q];
		for (i = 0; i < rxq->dma_rx_size; i++) {
			mbuf = rxq->rx_mbuf[i];
			rxq->rx_mbuf[i] = NULL;
			rte_pktmbuf_free(mbuf);
		}
	}

	for (q = 0; q < dev->data->nb_tx_queues; q++) {
		txq = private->tx_queues[q];
		for (i = 0; i < txq->dma_tx_size; i++) {
			mbuf = txq->tx_mbuf[i];
			txq->tx_mbuf[i] = NULL;
			rte_pktmbuf_free(mbuf);
		}
	}
}

static int
stmmac_eth_configure(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;

	if (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM)
		private->flag_csum |= RX_FLAG_CSUM_EN;

	if (dev->data->dev_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
		STMMAC_PMD_ERR("PMD does not support KEEP_CRC offload");

	return 0;
}

static int
stmmac_eth_start(struct rte_eth_dev *dev)
{
	stmmac_start(dev);
	dev->rx_pkt_burst = &stmmac_recv_pkts;
	dev->tx_pkt_burst = &stmmac_xmit_pkts;

	return 0;
}

/* STMMAC disable function.
 * @param[in] base      STMMAC base address
 */
static void
stmmac_disable(struct stmmac_private *private)
{
	stmmac_stop_all_dma(private);
}

static int
stmmac_eth_stop(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;
	struct stmmac_rx_queue *rxq;
	struct stmmac_tx_queue *txq;
	unsigned int q;

	dev->data->dev_started = 0;
	stmmac_disable(private);

	for (q = 0; q < dev->data->nb_rx_queues; q++) {
		STMMAC_PMD_ERR("stmmac_eth_stop rx queue");
		rxq = private->rx_queues[q];
		rxq->cur_rx = 0;
	}

	for (q = 0; q < dev->data->nb_tx_queues; q++) {
		STMMAC_PMD_ERR("stmmac_eth_stop tx queue");
		txq = private->tx_queues[q];
		txq->cur_tx = 0;
	}

	return 0;
}

static int
stmmac_eth_close(struct rte_eth_dev *dev)
{
	stmmac_free_buffers(dev);
	return 0;
}

static int
stmmac_eth_link_update(struct rte_eth_dev *dev,
			int wait_to_complete __rte_unused)
{
	struct rte_eth_link link;
	unsigned int lstatus = 1;

	memset(&link, 0, sizeof(struct rte_eth_link));

	link.link_status = lstatus;
	link.link_speed = RTE_ETH_SPEED_NUM_1G;

	STMMAC_PMD_ERR("Port (%d) link is %s\n", dev->data->port_id, "Up");

	return rte_eth_linkstatus_set(dev, &link);
}

/* Set a MAC change in hardware. */
static int
stmmac_set_mac_address(struct rte_eth_dev *dev,
		    struct rte_ether_addr *addr)
{
	struct stmmac_private *private = dev->data->dev_private;

	/* Copy the MAC addr into the HW  */
	stmmac_set_umac_addr(private, private->hw, addr->addr_bytes, 0);

	rte_ether_addr_copy(addr, &dev->data->mac_addrs[0]);

	return 0;
}

static int
stmmac_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct stmmac_private *private = dev->data->dev_private;
	struct rte_eth_stats *eth_stats = &private->stats;

	stats->ipackets = eth_stats->ipackets;
	stats->ibytes = eth_stats->ibytes;
	stats->ierrors = eth_stats->ierrors;
	stats->opackets = eth_stats->opackets;
	stats->obytes = eth_stats->obytes;
	stats->oerrors = eth_stats->oerrors;
	stats->rx_nombuf = eth_stats->rx_nombuf;

	return 0;
}

static int
stmmac_eth_info(__rte_unused struct rte_eth_dev *dev,
		struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_pktlen = STMMAC_MAX_RX_PKT_LEN;
	dev_info->max_rx_queues = STMMAC_MAX_Q;
	dev_info->max_tx_queues = STMMAC_MAX_Q;
	dev_info->rx_offload_capa = dev_rx_offloads_sup;
	return 0;
}

static void
stmmac_free_queue(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;
	unsigned int i;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		rte_free(private->rx_queues[i]);
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		rte_free(private->rx_queues[i]);
}

static void
stmmac_clear_rx_descriptors(struct stmmac_private *priv, uint32_t queue)
{
	struct stmmac_rx_queue *rx_q = priv->rx_queues[queue];
	unsigned int i;

	/* Clear the RX descriptors */
	for (i = 0; i < rx_q->dma_rx_size; i++)
		if (priv->extend_desc)
			stmmac_init_rx_desc(priv, &rx_q->dma_erx[i].basic,
					priv->use_riwt, priv->mode,
					(i == priv->dma_rx_size - 1),
					priv->dma_buf_sz);
		else
			stmmac_init_rx_desc(priv, &rx_q->dma_rx[i],
					priv->use_riwt, priv->mode,
					(i == priv->dma_rx_size - 1),
					priv->dma_buf_sz);
}

/**
 * stmmac_clear_tx_descriptors - clear tx descriptors
 * @priv: driver private structure
 * @queue: TX queue index.
 * Description: this function is called to clear the TX descriptors
 * in case of both basic and extended descriptors are used.
 */
static void
stmmac_clear_tx_descriptors(struct stmmac_private *priv, uint32_t queue)
{
	struct stmmac_tx_queue *tx_q = priv->tx_queues[queue];
	unsigned int i;

	/* Clear the TX descriptors */
	for (i = 0; i < tx_q->dma_tx_size; i++) {
		int last = (i == (priv->dma_tx_size - 1));
		struct dma_desc *p;

		if (priv->extend_desc)
			p = &tx_q->dma_etx[i].basic;
		else if (tx_q->tbs & STMMAC_TBS_AVAIL)
			p = &tx_q->dma_entx[i].basic;
		else
			p = &tx_q->dma_tx[i];

		stmmac_init_tx_desc(priv, p, priv->mode, last);
	}
}

/**
 * stmmac_init_rx_buffers - init the RX descriptor buffer.
 * @priv: driver private structure
 * @p: descriptor pointer
 * @i: descriptor index
 * @flags: gfp flag
 * @queue: RX queue index
 * Description: this function is called to allocate a receive buffer, perform
 * the DMA mapping and init the descriptor.
 */
static int
stmmac_init_rx_buffers(struct stmmac_private *priv, struct dma_desc *p,
		       struct rte_mbuf *buf)
{
	stmmac_set_desc_addr(priv, p, rte_cpu_to_le_32(rte_pktmbuf_iova(buf)));
	if (priv->dma_buf_sz == BUF_SIZE_16KiB)
		stmmac_init_desc3(priv, p);

	return 0;
}

static int
stmmac_tx_queue_setup(struct rte_eth_dev *dev,
		      uint16_t queue_idx,
		      uint16_t nb_desc,
		      unsigned int socket_id __rte_unused,
		      const struct rte_eth_txconf *tx_conf)
{
	struct stmmac_private *private = dev->data->dev_private;
	struct stmmac_tx_queue *txq =  private->tx_queues[queue_idx];
	unsigned int i;
	int ret;

	/* Tx deferred start is not supported */
	if (tx_conf->tx_deferred_start) {
		STMMAC_PMD_ERR("Tx deferred start not supported\n");
		return -EINVAL;
	}

	/* allocate transmit queue */
	txq = rte_zmalloc(NULL, sizeof(*txq), RTE_CACHE_LINE_SIZE);
	if (txq == NULL) {
		STMMAC_PMD_ERR("transmit queue allocation failed\n");
		return -ENOMEM;
	}

	if (nb_desc > DMA_MAX_TX_SIZE) {
		nb_desc = DMA_MAX_TX_SIZE;
		STMMAC_PMD_WARN("modified the nb_desc to MAX_TX_BD_RING_SIZE\n");
	}

	txq->dma_tx_size = nb_desc;
	private->total_tx_ring_size += txq->dma_tx_size;
	private->tx_queues[queue_idx] = txq;
	txq->dma_tx = private->bd_addr_t_v;
	txq->dma_tx_phy = private->bd_addr_t_p;
	txq->private = private;

	txq->tx_mbuf_dma = rte_zmalloc(NULL, nb_desc * sizeof(struct stmmac_tx_info), 0);
	if (txq->tx_mbuf_dma == NULL) {
		STMMAC_PMD_ERR("transmit queue tx_mbuf_dma allocation failed\n");
		ret = -ENOMEM;
		goto fail;
	}

	stmmac_clear_tx_descriptors(private, queue_idx);
	STMMAC_PMD_INFO("%s nb_desc: %d, total_tx_ring_size: %d\n", __func__,
			nb_desc, private->total_tx_ring_size);

	for (i = 0; i <txq->dma_tx_size; i++) {
		struct dma_desc *p;
		if (private->extend_desc)
			p = &((txq->dma_etx + i)->basic);
		else if (txq->tbs & STMMAC_TBS_AVAIL)
			p = &((txq->dma_entx + i)->basic);
		else
			p = txq->dma_tx + i;

		stmmac_clear_desc(private, p);

		txq->tx_mbuf_dma[i].buf = 0;
		txq->tx_mbuf_dma[i].len = 0;
		txq->tx_mbuf_dma[i].last_segment = false;
		txq->tx_mbuf[i] = NULL;
	}

	txq->dirty_tx = 0;
	txq->cur_tx = 0;
	txq->mss = 0;

	dev->data->tx_queues[queue_idx] = private->tx_queues[queue_idx];

	return 0;
fail:
	if (txq)
		rte_free(txq);

	return ret;
}

static int
stmmac_rx_queue_setup(struct rte_eth_dev *dev,
		      uint16_t queue_idx,
		      uint16_t nb_rx_desc,
		      unsigned int socket_id __rte_unused,
		      const struct rte_eth_rxconf *rx_conf,
		      struct rte_mempool *mb_pool)
{
	struct stmmac_private *private = dev->data->dev_private;
	struct stmmac_rx_queue *rxq;
	unsigned int i;
	int ret;

	/* Rx deferred start is not supported */
	if (rx_conf->rx_deferred_start) {
		STMMAC_PMD_ERR("Rx deferred start not supported\n");
		return -EINVAL;
	}

	/* allocate receive queue */
	rxq = rte_zmalloc(NULL, sizeof(*rxq), RTE_CACHE_LINE_SIZE);
	if (rxq == NULL) {
		STMMAC_PMD_ERR("receive queue allocation failed\n");
		return -ENOMEM;
	}

	if (nb_rx_desc > DMA_MAX_RX_SIZE) {
		nb_rx_desc = DMA_MAX_RX_SIZE;
		STMMAC_PMD_WARN("modified the nb_desc to MAX_RX_BD_RING_SIZE\n");
	}

	rxq->dma_rx_size = nb_rx_desc;
	private->total_rx_ring_size += rxq->dma_rx_size;
	private->rx_queues[queue_idx] = rxq;
	rxq->pool = mb_pool;
	rxq->private = private;
	rxq->queue_index = queue_idx;
	rxq->dma_rx = private->bd_addr_r_v;
	rxq->dma_rx_phy = private->bd_addr_r_p;

	STMMAC_PMD_INFO("%s nb_rx_desc: %d, total_rx_ring_size: %d\n",
			__func__, nb_rx_desc, private->total_rx_ring_size);

	stmmac_clear_rx_descriptors(private, queue_idx);

	for (i = 0; i < rxq->dma_rx_size; i++) {
		struct dma_desc *p;
		void *data;
		int size;
		/* Initialize Rx buffers from pktmbuf pool */
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mb_pool);
		if (mbuf == NULL) {
			STMMAC_PMD_ERR("mbuf failed");
			ret = -ENOMEM;
			goto err_alloc;
		}
		data = rte_pktmbuf_mtod(mbuf, uint8_t *);
		for (size = 0; size <= STMMAC_ALIGN_LENGTH; size += 64) {
			dcivac((uint8_t *)data + i);
		}

		if (private->extend_desc)
			p = &((rxq->dma_erx + i)->basic);
		else
			p = rxq->dma_rx + i;

		stmmac_init_rx_buffers(private, p, mbuf);
		rxq->rx_mbuf[i] = mbuf;
	}

	rxq->cur_rx = 0;
	rxq->dirty_rx = (unsigned int)(i - private->dma_rx_size);

	/* Setup the chained descriptor addresses */
	if (private->mode == STMMAC_CHAIN_MODE) {
		if (private->extend_desc)
			stmmac_mode_init(private, rxq->dma_erx,
					 rxq->dma_rx_phy,
					 rxq->dma_rx_size, 1);
		else
			stmmac_mode_init(private, rxq->dma_rx,
					 rxq->dma_rx_phy,
					 rxq->dma_rx_size, 0);
	}

	dev->data->rx_queues[queue_idx] = private->rx_queues[queue_idx];
	rxq->rx_tail_addr = rxq->dma_rx_phy +
			    (rxq->dma_rx_size * sizeof(struct dma_desc));
	wmb();
	stmmac_set_rx_tail_ptr(rxq->private, rxq->private->ioaddr_v, rxq->rx_tail_addr, 0);


	return 0;

err_alloc:
	rte_free(rxq);

	return ret;
}

#define GMAC_PACKET_FILTER		0x00000008
#define GMAC_PACKET_FILTER_PR		BIT(0)

static int
stmmac_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;
	uint32_t tmp;

	private->flags |= IFF_PROMISC;
	tmp = rte_read32((uint8_t *)private->ioaddr_v + GMAC_PACKET_FILTER);
	tmp |= GMAC_PACKET_FILTER_PR;
	rte_write32(rte_cpu_to_le_32(tmp),
		(uint8_t *)private->ioaddr_v + GMAC_PACKET_FILTER);

	return 0;
}

static int
stmmac_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;
	uint32_t tmp;

	private->flags &= ~IFF_PROMISC;
	tmp = rte_read32((uint8_t *)private->ioaddr_v + GMAC_PACKET_FILTER);
	tmp &= ~GMAC_PACKET_FILTER_PR;
	rte_write32(rte_cpu_to_le_32(tmp),
		(uint8_t *)private->ioaddr_v + GMAC_PACKET_FILTER);

	return 0;
}

static int
stmmac_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;

	private->flags |= IFF_ALLMULTI;
	/* To-do */

	return 0;
}

static int
stmmac_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;

	private->flags &= ~IFF_ALLMULTI;
	/* To-do */

	return 0;
}
static const struct eth_dev_ops stmmac_dev_ops = {
	.dev_configure          = stmmac_eth_configure,
	.dev_start              = stmmac_eth_start,
	.dev_stop               = stmmac_eth_stop,
	.dev_close              = stmmac_eth_close,
	.link_update            = stmmac_eth_link_update,
	.promiscuous_enable     = stmmac_promiscuous_enable,
	.promiscuous_disable	= stmmac_promiscuous_disable,
	.allmulticast_enable	= stmmac_allmulticast_enable,
	.allmulticast_disable	= stmmac_allmulticast_disable,
	.mac_addr_set           = stmmac_set_mac_address,
	.stats_get              = stmmac_stats_get,
	.dev_infos_get          = stmmac_eth_info,
	.rx_queue_setup         = stmmac_rx_queue_setup,
	.tx_queue_setup         = stmmac_tx_queue_setup
};

static int
stmmac_eth_init(struct rte_eth_dev *dev)
{
	struct stmmac_private *private = dev->data->dev_private;

	private->full_duplex = FULL_DUPLEX;
	dev->dev_ops = &stmmac_dev_ops;
	rte_eth_dev_probing_finish(dev);

	return 0;
}

static int
pmd_stmmac_probe(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;
	struct stmmac_private *private;
	const char *name;
	struct rte_ether_addr macaddr = {
		.addr_bytes = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 }
	};
	int rc, i, id = 0, fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq req;
	char if_name[16] = {0};

	name = rte_vdev_device_name(vdev);
	STMMAC_PMD_LOG(INFO, "Initializing pmd_stmmac for %s\n", name);

	if (strncmp(name, RTE_STR(STMMAC_NAME_PMD), sizeof(RTE_STR(STMMAC_NAME_PMD))) > 0) {
		sscanf(&name[strlen(RTE_STR(STMMAC_NAME_PMD))], "%d", &id);
		STMMAC_PMD_LOG(INFO, "Initializing pmd_stmmac for id %d\n", id);
	}

	dev = rte_eth_vdev_allocate(vdev, sizeof(*private));
	if (dev == NULL)
		return -ENOMEM;

	/* setup board info structure */
	private = dev->data->dev_private;
	private->dev = dev;
	private->rx_queues_to_use = STMMAC_MAX_Q;
	private->tx_queues_to_use = STMMAC_MAX_Q;

	rc = stmmac_configure(private, id);
	if (rc != 0)
		return -ENOMEM;
	rc = config_stmmac_uio(private);
	if (rc != 0)
		return -ENOMEM;

	for (i = 0; i < private->rx_queues_to_use; i++) {
		private->desc_addr_p_r[i] = private->bd_addr_r_p;
		private->dma_baseaddr_v_r[i] = private->bd_addr_r_v;
		private->bd_addr_r_v = (uint8_t *)private->bd_addr_r_v + private->bd_r_size[i] * i;
		private->bd_addr_r_p = private->bd_addr_r_p + private->bd_r_size[i] * i;
	}

	for (i = 0; i < private->tx_queues_to_use; i++) {
		private->desc_addr_p_t[i] = private->bd_addr_t_p;
		private->dma_baseaddr_v_t[i] = private->bd_addr_t_v;
		private->bd_addr_t_v = (uint8_t *)private->bd_addr_t_v + private->bd_t_size[i] * i;
		private->bd_addr_t_p = private->bd_addr_t_p + private->bd_t_size[i] * i;
	}

	/* Copy the station address into the dev structure, */
	dev->data->mac_addrs = rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		STMMAC_PMD_ERR("Failed to allocate mem %d to store MAC addresses\n",
			       RTE_ETHER_ADDR_LEN);
		rc = -ENOMEM;
		goto err;
	}

	private->plat = rte_zmalloc("plat_stmmacenet_data", sizeof(*private->plat), 0);
	if (private->plat == NULL) {
		rc = -ENOMEM;
		goto err;
	}

	private->plat->has_gmac4 = true;
	private->plat->has_gmac = false;

	/* Initialize HW Interface */
	rc  = stmmac_hwif_init(private);
	if (rc )
		goto err;

	rc = stmmac_eth_init(dev);
	if (rc)
		goto failed_init;

	memset(&req, 0, sizeof(req));
	snprintf(if_name, sizeof(if_name), "%s%d", "eth", id);
	strcpy(req.ifr_name, if_name);
	rc = ioctl(fd, SIOCGIFHWADDR, &req);
	if (rc)
		goto failed_init;
	memcpy(macaddr.addr_bytes,                           
	       req.ifr_addr.sa_data, RTE_ETHER_ADDR_LEN);
	/*
	 * Set default mac address
	 */
	stmmac_set_mac_address(dev, &macaddr);

	return 0;

failed_init:
	if (private->plat)
	rte_free(private->plat);
		STMMAC_PMD_ERR("Failed to init");
err:
	rte_eth_dev_release_port(dev);
	
	return rc;
}

static int
pmd_stmmac_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;
	struct stmmac_private *private;
	int ret;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (eth_dev == NULL)
		return -ENODEV;

	private = eth_dev->data->dev_private;
	/* Free descriptor base of first RX queue as it was configured
	 * first in stmmac_eth_init().
	 */
	stmmac_free_queue(eth_dev);
	stmmac_eth_stop(eth_dev);

	ret = rte_eth_dev_release_port(eth_dev);
	if (ret != 0)
		return -EINVAL;

	STMMAC_PMD_INFO("Release stmmac sw device");
	stmmac_cleanup(private);

	return 0;
}

static struct rte_vdev_driver pmd_stmmac_drv = {
	.probe = pmd_stmmac_probe,
	.remove = pmd_stmmac_remove,
};

RTE_PMD_REGISTER_VDEV(STMMAC_NAME_PMD, pmd_stmmac_drv);
RTE_LOG_REGISTER_DEFAULT(stmmac_logtype_pmd, NOTICE);
