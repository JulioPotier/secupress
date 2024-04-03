<?php
defined( 'WP_UNINSTALL_PLUGIN' ) or die( 'Something went wrong.' );

$settings = get_site_option( 'secupress_settings' );

if ( is_array( $settings ) && ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) ) {
	// Deactivate the license.
	$settings['consumer_email'] = sanitize_email( $settings['consumer_email'] );
	$settings['consumer_key']   = sanitize_text_field( $settings['consumer_key'] );

	if ( ! empty( $settings['consumer_email'] ) && ! empty( $settings['consumer_key'] ) ) {
		$url  = 'https://secupress.me/';
		$url .= 'key-api/1.0/?' . http_build_query( array(
			'sp_action'  => 'deactivate_pro_license',
			'user_email' => $settings['consumer_email'],
			'user_key'   => $settings['consumer_key'],
		) );

		$args = array(
			'timeout'  => 0.01,
			'blocking' => false,
		);

		if ( ! function_exists( 'secupress_add_own_ua' ) ) {
			/** This filter is documented in wp-includes/class-http.php. */
			$user_agent      = apply_filters( 'http_headers_useragent', 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ) );
			$version         = '2.2.5.3';
			$args['headers'] = array(
				'X-SECUPRESS' => sprintf( '%s;SecuPress|%s|%s|;', $user_agent, $version, esc_url( home_url() ) ),
			);
		}

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
