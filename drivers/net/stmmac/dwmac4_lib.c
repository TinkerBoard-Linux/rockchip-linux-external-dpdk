/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Fuzhou Rockchip Electronics Co., Ltd
 */

#include "common.h"
#include "dwmac4_dma.h"
#include "dwmac4.h"

int dwmac4_dma_reset(void *ioaddr)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_BUS_MODE);
	int limit;

	/* DMA SW reset */
	value |= DMA_BUS_MODE_SFT_RESET;
	rte_write32(value, (uint8_t *)ioaddr + DMA_BUS_MODE);
	limit = 10;
	while (limit--) {
		if (!(rte_read32((uint8_t *)ioaddr + DMA_BUS_MODE) & DMA_BUS_MODE_SFT_RESET))
			break;
		rte_delay_us(10 * 1000);
	}

	if (limit < 0)
		return -EBUSY;

	return 0;
}

void dwmac4_set_rx_tail_ptr(void  *ioaddr, uint32_t tail_ptr, uint32_t chan)
{
	rte_write32(tail_ptr, (uint8_t *)ioaddr + DMA_CHAN_RX_END_ADDR(chan));
}

void dwmac4_set_tx_tail_ptr(void  *ioaddr, uint32_t tail_ptr, uint32_t chan)
{
	rte_write32(tail_ptr, (uint8_t *)ioaddr + DMA_CHAN_TX_END_ADDR(chan));
}

void dwmac4_dma_start_tx(void  *ioaddr, uint32_t chan)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_TX_CONTROL(chan));

	value |= DMA_CONTROL_ST;
	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_TX_CONTROL(chan));

	value = rte_read32((uint8_t *)ioaddr + GMAC_CONFIG);
	value |= GMAC_CONFIG_TE;
	rte_write32(value, (uint8_t *)ioaddr + GMAC_CONFIG);
}

void dwmac4_dma_stop_tx(void  *ioaddr, uint32_t chan)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_TX_CONTROL(chan));

	value &= ~DMA_CONTROL_ST;
	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_TX_CONTROL(chan));
}

void dwmac4_dma_start_rx(void  *ioaddr, uint32_t chan)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_RX_CONTROL(chan));

	value |= DMA_CONTROL_SR;

	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_RX_CONTROL(chan));

	value = rte_read32((uint8_t *)ioaddr + GMAC_CONFIG);
	value |= GMAC_CONFIG_RE;
	rte_write32(value, (uint8_t *)ioaddr + GMAC_CONFIG);
}

void dwmac4_dma_stop_rx(void  *ioaddr, uint32_t chan)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_RX_CONTROL(chan));

	value &= ~DMA_CONTROL_SR;
	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_RX_CONTROL(chan));
}

void dwmac4_set_tx_ring_len(void  *ioaddr, uint32_t len, uint32_t chan)
{
	rte_write32(len, (uint8_t *)ioaddr + DMA_CHAN_TX_RING_LEN(chan));
}

void dwmac4_set_rx_ring_len(void  *ioaddr, uint32_t len, uint32_t chan)
{
	rte_write32(len, (uint8_t *)ioaddr + DMA_CHAN_RX_RING_LEN(chan));
}

void dwmac4_enable_dma_irq(void  *ioaddr, uint32_t chan, bool rx, bool tx)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));

	if (rx)
		value |= DMA_CHAN_INTR_DEFAULT_RX;
	if (tx)
		value |= DMA_CHAN_INTR_DEFAULT_TX;

	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));
}

void dwmac410_enable_dma_irq(void  *ioaddr, uint32_t chan, bool rx, bool tx)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));

	if (rx)
		value |= DMA_CHAN_INTR_DEFAULT_RX_4_10;
	if (tx)
		value |= DMA_CHAN_INTR_DEFAULT_TX_4_10;

	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));
}

void dwmac4_disable_dma_irq(void  *ioaddr, uint32_t chan, bool rx, bool tx)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));

	if (rx)
		value &= ~DMA_CHAN_INTR_DEFAULT_RX;
	if (tx)
		value &= ~DMA_CHAN_INTR_DEFAULT_TX;

	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));
}

void dwmac410_disable_dma_irq(void  *ioaddr, uint32_t chan, bool rx, bool tx)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));

	if (rx)
		value &= ~DMA_CHAN_INTR_DEFAULT_RX_4_10;
	if (tx)
		value &= ~DMA_CHAN_INTR_DEFAULT_TX_4_10;

	rte_write32(value, (uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));
}

int dwmac4_dma_interrupt(void  *ioaddr,
			 struct stmmac_extra_stats *x, uint32_t chan)
{
	uint32_t intr_status = rte_read32((uint8_t *)ioaddr + DMA_CHAN_STATUS(chan));
	uint32_t intr_en = rte_read32((uint8_t *)ioaddr + DMA_CHAN_INTR_ENA(chan));
	int ret = 0;

	/* ABNORMAL interrupts */
	if (unlikely(intr_status & DMA_CHAN_STATUS_AIS)) {
		if (unlikely(intr_status & DMA_CHAN_STATUS_RBU))
			x->rx_buf_unav_irq++;
		if (unlikely(intr_status & DMA_CHAN_STATUS_RPS))
			x->rx_process_stopped_irq++;
		if (unlikely(intr_status & DMA_CHAN_STATUS_RWT))
			x->rx_watchdog_irq++;
		if (unlikely(intr_status & DMA_CHAN_STATUS_ETI))
			x->tx_early_irq++;
		if (unlikely(intr_status & DMA_CHAN_STATUS_TPS)) {
			x->tx_process_stopped_irq++;
			ret = tx_hard_error;
		}
		if (unlikely(intr_status & DMA_CHAN_STATUS_FBE)) {
			x->fatal_bus_error_irq++;
			ret = tx_hard_error;
		}
	}
	/* TX/RX NORMAL interrupts */
	if (likely(intr_status & DMA_CHAN_STATUS_NIS)) {
		x->normal_irq_n++;
		if (likely(intr_status & DMA_CHAN_STATUS_RI)) {
			x->rx_normal_irq_n++;
			ret |= handle_rx;
		}
		if (likely(intr_status & (DMA_CHAN_STATUS_TI |
					  DMA_CHAN_STATUS_TBU))) {
			x->tx_normal_irq_n++;
			ret |= handle_tx;
		}
		if (unlikely(intr_status & DMA_CHAN_STATUS_ERI))
			x->rx_early_irq++;
	}

	rte_write32(intr_status & intr_en, (uint8_t *)ioaddr + DMA_CHAN_STATUS(chan));
	return ret;
}

void stmmac_dwmac4_set_mac_addr(void  *ioaddr, uint8_t addr[6],
				unsigned int high, unsigned int low)
{
	unsigned long data;

	data = (addr[5] << 8) | addr[4];
	/* For MAC Addr registers se have to set the Address Enable (AE)
	 * bit that has no effect on the High Reg 0 where the bit 31 (MO)
	 * is RO.
	 */
	data |= (STMMAC_CHAN0 << GMAC_HI_DCS_SHIFT);
	rte_write32(data | GMAC_HI_REG_AE, (uint8_t *)ioaddr + high);
	data = (addr[3] << 24) | (addr[2] << 16) | (addr[1] << 8) | addr[0];
	rte_write32(data, (uint8_t *)ioaddr + low);
}

/* Enable disable MAC RX/TX */
void stmmac_dwmac4_set_mac(void  *ioaddr, bool enable)
{
	uint32_t value = rte_read32((uint8_t *)ioaddr + GMAC_CONFIG);

	if (enable)
		value |= GMAC_CONFIG_RE | GMAC_CONFIG_TE;
	else
		value &= ~(GMAC_CONFIG_TE | GMAC_CONFIG_RE);

	rte_write32(value, (uint8_t *)ioaddr + GMAC_CONFIG);
}

void stmmac_dwmac4_get_mac_addr(void  *ioaddr, unsigned char *addr,
				unsigned int high, unsigned int low)
{
	unsigned int hi_addr, lo_addr;

	/* Read the MAC address from the hardware */
	hi_addr = rte_read32((uint8_t *)ioaddr + high);
	lo_addr = rte_read32((uint8_t *)ioaddr + low);

	/* Extract the MAC address from the high and low words */
	addr[0] = lo_addr & 0xff;
	addr[1] = (lo_addr >> 8) & 0xff;
	addr[2] = (lo_addr >> 16) & 0xff;
	addr[3] = (lo_addr >> 24) & 0xff;
	addr[4] = hi_addr & 0xff;
	addr[5] = (hi_addr >> 8) & 0xff;
}
