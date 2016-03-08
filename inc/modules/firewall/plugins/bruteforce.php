<?php
/*
Module Name: Anti Front Brute Force.
Description: Don't poll too hard on my website, thanks
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

define( 'SECUPRESS_BRUTEFORCE_TABLE', $GLOBALS['wpdb']->prefix . 'secupress_bruteforce' );

/**
 * Create our brute force table to contains every IP address that reach the website 
 * Set the option that the table is installed
 * Schedule the purge event to avoid huge useless table
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_activate_plugin_' . basename( __FILE__, '.php' ), 'secupress_bruteforce_activation' );
function secupress_bruteforce_activation() {
	global $wpdb;

	if ( $wpdb->get_var( 'SHOW TABLES LIKE "' . SECUPRESS_BRUTEFORCE_TABLE .'"' ) != SECUPRESS_BRUTEFORCE_TABLE ) {
		$sql = 'CREATE TABLE ' . SECUPRESS_BRUTEFORCE_TABLE . ' (
			id varchar(32) NOT NULL,
			timestamp bigint(20) NOT NULL,
			hits bigint(20) DEFAULT 1 NOT NULL,
			UNIQUE KEY id (id)
		);';
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql );
		update_option( 'secupress_bruteforce_installed', 1 );
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'secupress_bruteforce_purge_old_timestamps' );
	}
}

/**
 * Used during the cron, will purge the old timestamps
 *
 * @since 1.0
 * @return void
 **/
function secupress_bruteforce_purge_old_timestamps() {
	global $wpdb;
	$wpdb->get_row( $wpdb->prepare( 'DELETE FROM ' . SECUPRESS_BRUTEFORCE_TABLE . ' WHERE timestamp < %s', time() ) );
}

/**
 * Drop our table
 * Delete our option
 * Remove the event
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_deactivate_plugin_' . basename( __FILE__, '.php' ), 'secupress_bruteforce_deactivation' );
function secupress_bruteforce_deactivation() {
	global $wpdb;
	$wpdb->query( 'DROP TABLE ' . SECUPRESS_BRUTEFORCE_TABLE );
	delete_option( 'secupress_bruteforce_installed' );
	wp_unschedule_event( time(), 'secupress_bruteforce_purge_old_timestamps' );
}

/**
 * Will insert/update hits on page load for a given IP address and will ban it if needed
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_plugins_loaded', 'secupress_check_bruteforce' );
function secupress_check_bruteforce() {
	global $wpdb;

	if ( current_user_can( 'administrator' ) || ! get_option( 'secupress_bruteforce_installed' ) ) {
		return;
	}

	$IP   = secupress_get_ip();
	$time = time();
	$id   = md5( $IP . $time . wp_salt( 'nonce' ) );
	$hits = secupress_get_module_option( 'bruteforce_request_number', 9, 'firewall' );

	$wpdb->query( $wpdb->prepare( 'INSERT INTO ' . SECUPRESS_BRUTEFORCE_TABLE . ' ( id, timestamp ) VALUES ( %s, %d ) ON DUPLICATE KEY UPDATE hits = hits+1', $id, $time ) );
	$result = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . SECUPRESS_BRUTEFORCE_TABLE . ' WHERE id = %s AND timestamp = %d AND hits >= %d LIMIT 1', $id, $time, $hits ) );

	if ( $result ) {
		/**
		 * Fires before we ban the IP address that just brute force us.
		 *
		 * @since 1.0
		 */		
		do_action( 'secupress.plugin.bruteforce.triggered', $IP, $hits, $id );
		$wpdb->delete( SECUPRESS_BRUTEFORCE_TABLE, array( 'id' => $id ) );
		$time_ban = secupress_get_module_option( 'bruteforce_time_ban', 5, 'firewall' );
		secupress_ban_ip( $time_ban );
	}

}