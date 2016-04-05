<?php
// If uninstall not called from WordPress exit
defined( 'WP_UNINSTALL_PLUGIN' ) or die( 'Cheatin&#8217; uh?' );

global $wpdb;

// Transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_secupress_%'" );

if ( $transients ) {
	foreach ( $transients as $option_name ) {
		delete_transient( $option_name );
	}
}

// Site transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_site_transient_secupress_%'" );

if ( $transients ) {
	foreach ( $transients as $option_name ) {
		delete_site_transient( $option_name );
	}
}

if ( is_multisite() ) {
	$transients = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE '_site_transient_secupress_%'" );

	if ( $transients ) {
		foreach ( $transients as $option_name ) {
			delete_site_transient( $option_name );
		}
	}
}

// Options.
$options = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE 'secupress_%'" );

if ( $options ) {
	foreach ( $options as $option_name ) {
		delete_option( $option_name );
	}
}

if ( is_multisite() ) {
	// Site options
	$options = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE 'secupress_%'" );

	if ( $options ) {
		foreach ( $options as $option_name ) {
			delete_site_option( $option_name );
		}
	}
}

// User metas.
$wpdb->query( "DELETE FROM $wpdb->usermeta WHERE meta_key LIKE '%dismissed_secupress_notices'" );
