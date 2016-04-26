<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'init', 'secupress_purge_cron_scheduled' );
/**
 * Planning cron.
 * If the task is not programmed, it is automatically triggered.
 *
 * @since 1.0
 */
function secupress_purge_cron_scheduled() {
	if ( 0 < (int) secupress_get_option( 'scan_cron_interval' ) && ! wp_next_scheduled( 'secupress_cron_scan' ) ) {
		wp_schedule_event( time(), 'daily', 'secupress_cron_scan' );
	}
}


/**
 * Perform a scan by cron.
 *
 * @since 1.0
 */
function secupress_cron_scan() {
	// ////
}
