<?php
/*
Module Name: GeoIP Management
Description: Whitelist or blacklist countries to visit your website.
Main Module: firewall
Author: SecuPress
Version: 1.0
*/
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

$wpdb->secupress_geoips = $wpdb->prefix . 'secupress_geoips';

/**
 * Get the country code of a given IP.
 *
 * @since 1.0
 *
 * @param (string) $ip An IP address.
 *
 * @return (string|null) A country code. Null if find nothing.
 **/
function secupress_geoip2country( $ip ) {
	global $wpdb;

	if ( '127.0.0.1' === $ip || '::1' === $ip ) {
		// Save a useless query >_>
		return null;
	}

	$ip2long = sprintf( "%u", ip2long( $ip ) );
	$var     = $wpdb->get_var( $wpdb->prepare( "SELECT country_code FROM $wpdb->secupress_geoips WHERE %d BETWEEN begin_ip AND end_ip LIMIT 1", $ip2long ) );

	return $var;
}


/**
 * Create our geoip table to contains every IP address around the world around the woOolrd.
 * Set the option that the table is installed.
 *
 * @since 1.0
 **/
add_action( 'secupress_activate_plugin_' . basename( __FILE__, '.php' ), 'secupress_geoip_activation' );

function secupress_geoip_activation() {
	global $wpdb;

	$filename = SECUPRESS_INC_PATH . 'data/geoips.data';
	$queries  = file_exists( $filename ) ? file_get_contents( $filename ) : false;

	if ( ! $queries ) {
		secupress_add_transient_notice( sprintf( __( 'The module GeoIP Management has not been activated because the file %s cannot be read.', 'secupress' ), '<code>' . str_replace( realpath( ABSPATH ), '', $filename ) . '</code>' ), 'error' );
		// Deactivate the plugin.
		secupress_manage_submodule( 'firewall', 'geoip-system', false );
		// Remove (de)activation notices.
		secupress_remove_module_notice( 'firewall', basename( __FILE__, '.php' ), 'activation' );
		secupress_remove_module_notice( 'firewall', basename( __FILE__, '.php' ), 'deactivation' );
		return;
	}

	// If the table exists, bail out.
	if ( $wpdb->get_var( "SHOW TABLES LIKE '$wpdb->secupress_geoips'" ) === $wpdb->secupress_geoips ) {
		return;
	}

	// Create the table and fill in the data.
	$sql = "CREATE TABLE $wpdb->secupress_geoips (
		id int(10) unsigned NOT NULL AUTO_INCREMENT,
		begin_ip bigint(20) COLLATE utf8_unicode_ci DEFAULT NULL,
		end_ip bigint(20) COLLATE utf8_unicode_ci DEFAULT NULL,
		country_code varchar(3) COLLATE utf8_unicode_ci DEFAULT NULL,
		PRIMARY KEY (id),
		KEY begin_ip (begin_ip, end_ip)
	);";

	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
	dbDelta( $sql );

	$queries = explode( "\n", gzinflate( $queries ) );
	$queries = array_chunk( $queries, 1000 );

	foreach ( $queries as $query ) {
		$query = rtrim( rtrim( implode( "),\n(", $query ) ), ',' );
		$wpdb->query( "INSERT INTO $wpdb->secupress_geoips (begin_ip, end_ip, country_code) VALUES ($query)" );
	}

	update_option( 'secupress_geoip_installed', 1 );
}


/**
 * Drop our table.
 * Delete our option.
 *
 * @since 1.0
 **/
add_action( 'secupress_deactivate_plugin_' . basename( __FILE__, '.php' ), 'secupress_geoip_deactivation' );

function secupress_geoip_deactivation() {
	global $wpdb;

	if ( $wpdb->get_var( "SHOW TABLES LIKE '$wpdb->secupress_geoips'" ) === $wpdb->secupress_geoips ) {
		$wpdb->query( "DROP TABLE $wpdb->secupress_geoips" );
	}

	delete_option( 'secupress_geoip_installed' );
}


/**
 * Get the country code and check if we need to block this IP address.
 *
 * @since 1.0
 **/
add_action( 'secupress_plugins_loaded', 'secupress_geoip_check_country' );

function secupress_geoip_check_country() {
	if ( ! get_option( 'secupress_geoip_installed' ) ) {
		return;
	}

	$ip = secupress_get_ip();

	if ( '127.0.0.1' === $ip ) {
		return;
	}

	$country_code = secupress_geoip2country( $ip );
	$is_whitelist = secupress_get_module_option( 'geoip-system_type', -1, 'firewall' ) === 'whitelist';
	$countries    = array_flip( secupress_get_module_option( 'geoip-system_countries', array(), 'firewall' ) );

	if ( ( isset( $countries[ $country_code ] ) && ! $is_whitelist ) || ( ! isset( $countries[ $country_code ] ) && $is_whitelist ) ) {
		secupress_block( 'GIP' );
	}
}
