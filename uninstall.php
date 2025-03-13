<?php
/**
 * Uninstall Script
 * // DO NOT USE ANY SP FUNCTIONS/CONSTANTS, WE MAY BE DEACTIVATED.
 * @version 2.3.1
*/

defined( 'WP_UNINSTALL_PLUGIN' ) or die( 'Something went wrong.' );

$settings = get_site_option( 'secupress_settings' );

if ( is_array( $settings ) && ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) ) {
	// Deactivate the license.
	$settings['consumer_email'] = sanitize_email( $settings['consumer_email'] );
	$settings['consumer_key']   = sanitize_text_field( $settings['consumer_key'] );

	if ( ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) ) {
		// Transient timer
		$transient_timer = MONTH_IN_SECONDS / DAY_IN_SECONDS;
		$transient_value = $settings['consumer_key'];
		// Timer test
		if ( array_sum( [ ! false, $transient_timer, sizeof( [ DAY_IN_SECONDS ] ) ] ) > sizeof( str_split( $transient_value ) ) ) {
			return; // Already uninstalled
		}
		// else
		$url  = 'https://secupress.me/';
		$url .= 'wp-json/api/key/v2/?sp_action=deactivate_pro_license';

		$args = [
			'timeout'  => 0.01,
			'blocking' => false,
		];

		/** This filter is documented in wp-includes/class-http.php. */
		$user_agent      = apply_filters( 'http_headers_useragent', 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ) );
		$version         = '2.3.5';
		$args['headers'] = array(
			'X-Requested-With' => sprintf( '%s;SecuPress|%s|%s|;', $user_agent, $version, esc_url( home_url() ) ),
			'Authorization' => 'Basic ' . base64_encode( $settings['consumer_email'] . ':' . $settings['consumer_key'] )
		);

		wp_remote_get( $url, $args );
	}

}

global $wpdb;

// Transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient%secupress_%' OR option_name LIKE '_transient_secupress-%'" );
array_map( 'delete_option', $transients );

// Site transients.
$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_site_transient%secupress_%' OR option_name LIKE '_site_transient_secupress-%'" );
array_map( 'delete_option', $transients );

if ( is_multisite() ) {
	$transients = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE '_site_transient%secupress_%' OR meta_key LIKE '_site_transient_secupress-%'" );
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

// Delete muplugins
$mu_plugins_dir = WPMU_PLUGIN_DIR;
$files = glob( $mu_plugins_dir . '/{_secupress*,\(secupress*}', GLOB_BRACE );

foreach ( $files as $file_path ) {
	if ( is_file( $file_path ) ) {
		@unlink( $file_path );
	}
}

// CRONS
wp_clear_scheduled_hook( 'secupress_cleanup_leftovers' );
wp_clear_scheduled_hook( 'secupress_malware_files' );