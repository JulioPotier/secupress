<?php
/*
Module Name: GeoIP Management
Description: Whitelist or blacklist countries to visit your website
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

define( 'SECUPRESS_GEOIP_TABLE', $GLOBALS['wpdb']->prefix . 'secupress_geoips' );

function secupress_geoip2country( $ip ) {
	global $wpdb;
	
	$ip2long = sprintf( "%u", ip2long( $ip ) );
	$var     = $wpdb->get_var( $wpdb->prepare( 'SELECT country_code FROM ' . SECUPRESS_GEOIP_TABLE . ' WHERE %d BETWEEN begin_ip AND end_ip LIMIT 1', $ip2long ) );
	
	return $var;
}

/**
 * Create our geoip table to contains every IP address around the world around the woOolrd
 * Set the option that the table is installed
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_activate_plugin_' . basename( __FILE__, '.php' ), 'secupress_geoip_activation' );
function secupress_geoip_activation() {
	global $wpdb;

	$filename = SECUPRESS_INC_PATH . 'data/geoips.data';
	$queries  = file_exists( $filename ) ? file_get_contents( $filename ) : false;
	if ( ! $queries ) {
		return; //// desactiver le plugin + signaler en notice ?
	}

	if ( $wpdb->get_var( 'SHOW TABLES LIKE "' . SECUPRESS_GEOIP_TABLE .'"' ) != SECUPRESS_GEOIP_TABLE ) {
		$sql = 'CREATE TABLE ' . SECUPRESS_GEOIP_TABLE . ' (
			id int(10) unsigned NOT NULL AUTO_INCREMENT,
			begin_ip bigint(20) COLLATE utf8_unicode_ci DEFAULT NULL,
			end_ip bigint(20) COLLATE utf8_unicode_ci DEFAULT NULL,
			country_code varchar(3) COLLATE utf8_unicode_ci DEFAULT NULL,
			PRIMARY KEY (id),
			KEY begin_ip (begin_ip, end_ip)
		);';
		require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
		dbDelta( $sql );
		$queries = explode( "\n", gzinflate( $queries ) );
		$queries = array_chunk( $queries, 1000 );
		foreach ( $queries as $query ) {
			$query = rtrim( rtrim( implode( "),\n(", $query ) ), ',' );
			$wpdb->query( 'INSERT INTO ' . SECUPRESS_GEOIP_TABLE . ' (begin_ip, end_ip, country_code) VALUES (' . $query . ')' );
		}
		update_option( 'secupress_geoip_installed', 1 );
	}
}

/**
 * Drop our table
 * Delete our option
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_deactivate_plugin_' . basename( __FILE__, '.php' ), 'secupress_geoip_deactivation' );
function secupress_geoip_deactivation() {
	global $wpdb;
	$wpdb->query( 'DROP TABLE ' . SECUPRESS_GEOIP_TABLE );
	delete_option( 'secupress_geoip_installed' );
}

/**
 * Get the country code and check if we need to block this IP address
 *
 * @since 1.0
 * @return void
 **/
add_action( 'secupress_plugins_loaded', 'secupress_geoip_check_country' );
function secupress_geoip_check_country() {
	$country_code = secupress_geoip2country( secupress_get_ip() );
	$countries    = array_flip( secupress_get_module_option( 'geoip-system_countries', -1, 'firewall' ) );
	$is_whitelist = secupress_get_module_option( 'geoip-system_type', -1, 'firewall' ) == 'whitelist';

	if ( ( isset( $countries[ $country_code ] ) && ! $is_whitelist ) ||
		( ! isset( $countries[ $country_code ] ) && $is_whitelist ) ) {
		secupress_block( 'GIP' );
	}
}