/*
 * Copyright 2012 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

/*
 * Tilera TILE-Gx USB OHCI host controller driver.
 */

#include <linux/irq.h>
#include <linux/platform_device.h>
#include <linux/usb/tilegx.h>
#include <linux/usb.h>

#include <asm/homecache.h>

#include <gxio/iorpc_usb_host.h>
#include <gxio/usb_host.h>

static void tilegx_start_ohc(void)
{
}

static void tilegx_stop_ohc(void)
{
}

static int tilegx_ohci_start(struct usb_hcd *hcd)
{
	struct ohci_hcd *ohci = hcd_to_ohci(hcd);
	int ret;

	ret = ohci_init(ohci);
	if (ret < 0)
		return ret;

	ret = ohci_run(ohci);
	if (ret < 0) {
		dev_err(hcd->self.controller, "can't start %s\n",
			hcd->self.bus_name);
		ohci_stop(hcd);
		return ret;
	}

	return 0;
}

static const struct hc_driver ohci_tilegx_hc_driver = {
	.description		= hcd_name,
	.product_desc		= "Tile-Gx OHCI",
	.hcd_priv_size		= sizeof(struct ohci_hcd),

	/*
	 * Generic hardware linkage.
	 */
	.irq			= ohci_irq,
	.flags			= HCD_MEMORY | HCD_LOCAL_MEM | HCD_USB11,

	/*
	 * Basic lifecycle operations.
	 */
	.start			= tilegx_ohci_start,
	.stop			= ohci_stop,
	.shutdown		= ohci_shutdown,

	/*
	 * Managing I/O requests and associated device resources.
	 */
	.urb_enqueue		= ohci_urb_enqueue,
	.urb_dequeue		= ohci_urb_dequeue,
	.endpoint_disable	= ohci_endpoint_disable,

	/*
	 * Scheduling support.
	 */
	.get_frame_number	= ohci_get_frame,

	/*
	 * Root hub support.
	 */
	.hub_status_data	= ohci_hub_status_data,
	.hub_control		= ohci_hub_control,
	.start_port_reset	= ohci_start_port_reset,
};

static int ohci_hcd_tilegx_drv_probe(struct platform_device *pdev)
{
	struct usb_hcd *hcd;
	struct tilegx_usb_platform_data *pdata = pdev->dev.platform_data;
	pte_t pte = { 0 };
	int my_cpu = smp_processor_id();
	int ret;

	if (usb_disabled())
		return -ENODEV;

	/*
	 * Try to initialize our GXIO context; if we can't, the device
	 * doesn't exist.
	 */
	if (gxio_usb_host_init(&pdata->usb_ctx, pdata->dev_index, 0) != 0)
		return -ENXIO;

	hcd = usb_create_hcd(&ohci_tilegx_hc_driver, &pdev->dev,
			     dev_name(&pdev->dev));
	if (!hcd) {
		ret = -ENOMEM;
		goto err_hcd;
	}

	/*
	 * We don't use rsrc_start to map in our registers, but seems like
	 * we ought to set it to something, so we use the register VA.
	 */
	hcd->rsrc_start =
		(ulong) gxio_usb_host_get_reg_start(&pdata->usb_ctx);
	hcd->rsrc_len = gxio_usb_host_get_reg_len(&pdata->usb_ctx);
	hcd->regs = gxio_usb_host_get_reg_start(&pdata->usb_ctx);

	tilegx_start_ohc();

	/* Create our IRQs and register them. */
	pdata->irq = create_irq();
	if (pdata->irq < 0) {
		ret = -ENXIO;
		goto err_no_irq;
	}

	tile_irq_activate(pdata->irq, TILE_IRQ_PERCPU);

	/* Configure interrupts. */
	ret = gxio_usb_host_cfg_interrupt(&pdata->usb_ctx,
					  cpu_x(my_cpu), cpu_y(my_cpu),
					  KERNEL_PL, pdata->irq);
	if (ret) {
		ret = -ENXIO;
		goto err_have_irq;
	}

	/* Register all of our memory. */
	pte = pte_set_home(pte, PAGE_HOME_HASH);
	ret = gxio_usb_host_register_client_memory(&pdata->usb_ctx, pte, 0);
	if (ret) {
		ret = -ENXIO;
		goto err_have_irq;
	}

	ohci_hcd_init(hcd_to_ohci(hcd));

	ret = usb_add_hcd(hcd, pdata->irq, IRQF_SHARED);
	if (ret == 0) {
		platform_set_drvdata(pdev, hcd);
		return ret;
	}

err_have_irq:
	destroy_irq(pdata->irq);
err_no_irq:
	tilegx_stop_ohc();
	usb_put_hcd(hcd);
err_hcd:
	gxio_usb_host_destroy(&pdata->usb_ctx);
	return ret;
}

static int ohci_hcd_tilegx_drv_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct tilegx_usb_platform_data* pdata = pdev->dev.platform_data;

	usb_remove_hcd(hcd);
	usb_put_hcd(hcd);
	tilegx_stop_ohc();
	gxio_usb_host_destroy(&pdata->usb_ctx);
	destroy_irq(pdata->irq);

	return 0;
}

static void ohci_hcd_tilegx_drv_shutdown(struct platform_device *pdev)
{
	usb_hcd_platform_shutdown(pdev);
	ohci_hcd_tilegx_drv_remove(pdev);
}

static struct platform_driver ohci_hcd_tilegx_driver = {
	.probe		= ohci_hcd_tilegx_drv_probe,
	.remove		= ohci_hcd_tilegx_drv_remove,
	.shutdown	= ohci_hcd_tilegx_drv_shutdown,
	.driver = {
		.name	= "tilegx-ohci",
		.owner	= THIS_MODULE,
	}
};

MODULE_ALIAS("platform:tilegx-ohci");
