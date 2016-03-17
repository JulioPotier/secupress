<?php
/*
Module Name: Anti Front Brute Force.
Description: Don't poll too hard on my website, thanks
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

$wpdb->secupress_bruteforce = $wpdb->prefix . 'secupress_bruteforce';

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
	if ( $wpdb->get_var( "SHOW TABLES LIKE '$wpdb->secupress_bruteforce'" ) === $wpdb->secupress_bruteforce ) {
		return;
	}
	$sql = "CREATE TABLE $wpdb->secupress_bruteforce (
		id varchar(32) NOT NULL,
		timestamp bigint(20) NOT NULL,
		hits bigint(20) DEFAULT 1 NOT NULL,
		UNIQUE KEY id (id)
	);";
	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
	dbDelta( $sql );
	update_option( 'secupress_bruteforce_installed', 1 );
	wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'secupress_bruteforce_purge_old_timestamps' );
}

/**
 * Used during the cron, will purge the old timestamps
 *
 * @since 1.0
 * @return void
 **/
function secupress_bruteforce_purge_old_timestamps() {
	global $wpdb;
	$wpdb->get_row( $wpdb->prepare( "DELETE FROM $wpdb->secupress_bruteforce WHERE timestamp < %s", time() ) );
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

	if ( $wpdb->get_var( "SHOW TABLES LIKE '$wpdb->secupress_bruteforce'" ) === $wpdb->secupress_bruteforce ) {
		$wpdb->query( "DROP TABLE $wpdb->secupress_bruteforce" );
	}
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
	global $wpdb, $pagenow;

	/**
	 * Set to true to avoid been locked by the Brute Force
	 * The goal is to easily manage any edge case
	 * Usage example: 
	 * add_filter( 'secupress.plugin.bruteforce.edgecase', '_manage_bruteforce_edgecase', 1 );
	 * function _manage_bruteforce_edgecase( $value ) {
	 *		if ( defined( 'SOME_CONSTANT' ) ) { // or any other test
	 *			return true;
	 *		}
	 *		return $value;
	 * }
	 *
	 * @param false or true
	 * @since 1.0
	 */
	$edged_case = apply_filters( 'secupress.plugin.bruteforce.edgecase', false );

	if ( $edge_case || current_user_can( 'administrator' ) || ! get_option( 'secupress_bruteforce_installed' ) || defined( 'DOING_AJAX' ) || ( is_admin() && 'admin-post.php' == $pagenow ) ) {
		return;
	}

	$IP           = secupress_get_ip();
	$time         = time();
	$method       = $_SERVER['REQUEST_METHOD'];
	$id           = md5( $method . $IP . $time . wp_salt( 'nonce' ) );
	switch( $method ) {
		case 'GET':  $hits = 9; break;
		case 'POST': $hits = 3; break;
		default:     $hots = 5; break;
	}
	/**
	 * Set a maximum hit times in 1 second, more than that = IP banned
	 *
	 * @param $hits How much hits maximum before being banned
	 * @param $method The request method
	 *
	 * @since 1.0
	 */
	$hits   = apply_filters( 'secupress.plugin.bruteforce.maxhits', $hits, $method );
	$wpdb->query( $wpdb->prepare( "INSERT INTO $wpdb->secupress_bruteforce ( id, timestamp ) VALUES ( %s, %d ) ON DUPLICATE KEY UPDATE hits = hits+1", $id, $time ) );
	$result = $wpdb->get_var( $wpdb->prepare( "SELECT hits FROM $wpdb->secupress_bruteforce WHERE id = %s AND timestamp = %d AND hits >= %d LIMIT 1", $id, $time, $hits ) );

	if ( $hits == $result ) {
		/**
		 * Fires before we ban the IP address that just brute force us.
		 *
		 * @param '>' or '=' means if the actual counter of hits, reach the hits, or ir superior
		 * @param $IP The IP address that triggered the event
		 * @param $hits How much hits the IP just did
		 * @param $id The id of the trigger
		 * @param $method The request method
		 * @since 1.0
		 */		
		do_action( 'secupress.plugin.bruteforce.triggered', '=', $IP, $hits, $id, $method );
		$time_ban = secupress_get_module_option( 'bruteforce_time_ban', 5, 'firewall' );
		secupress_die( sprintf( __( 'Slow down, you move too fast.<br>Please wait a while before opening a new page or your IP address <em>%s</em> will be blocked for %d minutes.', 'secupress' ), $IP, $time_ban ) );

	} elseif( $hits < $results ) {

		do_action( 'secupress.plugin.bruteforce.triggered', '>', $IP, $hits, $id, $method );
		$wpdb->delete( $wpdb->secupress_bruteforce, array( 'id' => $id ) );
		$time_ban = secupress_get_module_option( 'bruteforce_time_ban', 5, 'firewall' );
		secupress_ban_ip( $time_ban );

	}

}