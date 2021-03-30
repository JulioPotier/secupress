<?php
defined( 'WP_UNINSTALL_PLUGIN' ) or die( 'Something went wrong.' );

global $wpdb;

// Transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_secupress_%' OR option_name LIKE '_transient_secupress-%'" );
array_map( 'delete_option', $transients );

// Site transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_site_transient_secupress_%' OR option_name LIKE '_site_transient_secupress-%'" );
array_map( 'delete_option', $transients );

if ( is_multisite() ) {
	$transients = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE '_site_transient_secupress_%' OR meta_key LIKE '_site_transient_secupress-%'" );
	array_map( 'delete_option', $transients );
}

// Options.
$options = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE 'secupress_%'" );
array_map( 'delete_option', $options );

if ( is_multisite() ) {
	// Site options.
	$options = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE 'secupress_%'" );
	array_map( 'delete_site_option', $options );
}

// User metas.
$wpdb->query( "DELETE FROM $wpdb->usermeta WHERE meta_key LIKE 'secupress_%' OR meta_key LIKE '%_secupress_%'" );
