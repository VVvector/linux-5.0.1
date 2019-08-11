/*
 * Copyright (C) 2012 Thomas Petazzoni
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/of_irq.h>
#include <linux/irqchip.h>

/*
 * This special of_device_id is the sentinel at the end of the
 * of_device_id[] array of all irqchips. It is automatically placed at
 * the end of the array by the linker, thanks to being part of a
 * special section.
 */
static const struct of_device_id
irqchip_of_match_end __used __section(__irqchip_of_table_end);

extern struct of_device_id __irqchip_of_table[];

void __init irqchip_init(void)
{
	/*__irqchip_of_table 就是内核irq chip table的首地址，这个table也就保存了kernel支持的所有的中断控制器
	的驱动代码初始化函数和DT compatible string的对应关系。*/
	of_irq_init(__irqchip_of_table);
	acpi_probe_device_table(irqchip);
}
