// SPDX-License-Identifier: GPL-2.0
/*
 * RustGuard — C shim for periodic timer via workqueue.
 *
 * Uses a delayed_work that fires every 250ms to check peer state:
 * rekeying, keepalives, session expiry. Calls into Rust for the logic.
 */

#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

/* Prototypes. */
int wg_timer_start(void *rust_priv);
void wg_timer_stop(void);

/* Forward declaration — implemented in Rust. */
extern void rustguard_timer_tick(void *rust_priv);

static struct delayed_work wg_work;
static void *wg_timer_priv;
static bool wg_timer_running;

#define WG_TIMER_INTERVAL_MS 250

static void wg_timer_work(struct work_struct *work)
{
	if (!wg_timer_running || !wg_timer_priv)
		return;

	rustguard_timer_tick(wg_timer_priv);

	if (wg_timer_running)
		schedule_delayed_work(&wg_work,
				      msecs_to_jiffies(WG_TIMER_INTERVAL_MS));
}

int wg_timer_start(void *rust_priv)
{
	wg_timer_priv = rust_priv;
	wg_timer_running = true;
	INIT_DELAYED_WORK(&wg_work, wg_timer_work);
	schedule_delayed_work(&wg_work, msecs_to_jiffies(WG_TIMER_INTERVAL_MS));
	return 0;
}
EXPORT_SYMBOL_GPL(wg_timer_start);

void wg_timer_stop(void)
{
	wg_timer_running = false;
	cancel_delayed_work_sync(&wg_work);
	wg_timer_priv = NULL;
}
EXPORT_SYMBOL_GPL(wg_timer_stop);
