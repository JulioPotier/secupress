<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_action( 'admin_bar_menu', 'secupress_admin_bar', 100 );
/**
 * Add menu in tool bar.
 *
 * @since 1.0
 *
 * @param (object) $wp_admin_bar WP_Admin_Bar object.
 */
function secupress_admin_bar( $wp_admin_bar ) {
	if ( ! current_user_can( secupress_get_capability() ) ) {
		return;
	}

	// Add a counter of scans with good result.
	$counts = secupress_get_scanner_counts();

	if ( $counts['good'] || $counts['bad'] ) {
		// Translators: 1 is plugin name, 2 is a number for the percentage. Keep the double "%%".
		$count = sprintf( __( '%1$s: %2$d%% of the scanners are OK', 'secupress' ), SECUPRESS_PLUGIN_NAME, $counts['good'] * 100 / $counts['total'] );
		$grade = esc_attr( sprintf( __( 'Grade %s', 'secupress' ), $counts['grade'] ) );
	} else {
		$count = '';
		$grade = '';
	}

	// Parent.
	$wp_admin_bar->add_menu( array(
		'id'    => 'secupress',
		'title' => '<span class="ab-icon dashicons-shield-alt"></span><span class="screen-reader-text">' . SECUPRESS_PLUGIN_NAME . ' </span>' . $grade,
		'meta'  => array(
			'title' => $count,
		),
	) );

	// Scanners.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-scanners',
		'title'  => __( 'Scanners', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'secupress_scanners' ) ),
	) );

	// Modules.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-modules',
		'title'  => __( 'Modules', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'secupress_modules' ) ),
	) );

	// Settings.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-settings',
		'title'  => __( 'Settings', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'secupress_settings' ) ),
	) );
}
