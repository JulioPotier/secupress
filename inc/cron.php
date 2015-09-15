<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Planning cron
 * If the task is not programmed, it is automatically triggered
 *
 * @since 1.0
 */
add_action( 'init', 'secupress_purge_cron_scheduled' );
function secupress_purge_cron_scheduled()
{
	if ( 0 < (int) secupress_get_option( 'scan_cron_interval' ) && ! wp_next_scheduled( 'secupress_cron_scan' ) ) {
		wp_schedule_event( time(), 'daily', 'secupress_cron_scan' );
	}
}

function secupress_cron_scan() {

}