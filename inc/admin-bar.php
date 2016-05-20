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
		$grade = sprintf( __( 'Grade %s', 'secupress' ), '<span class="letter">' . $counts['grade'] . '</span>' );
	} else {
		$grade = '';
	}

	// Parent.
	$wp_admin_bar->add_menu( array(
		'id'    => 'secupress',
		'title' => '<span class="ab-icon dashicons-shield-alt"></span><span class="screen-reader-text">' . SECUPRESS_PLUGIN_NAME . ' </span>' . $grade,
	) );

	// Scanners.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-scanners',
		'title'  => __( 'Scanners', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'scanners' ) ),
	) );

	// Modules.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-modules',
		'title'  => __( 'Modules', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'modules' ) ),
	) );

	// Settings.
	$wp_admin_bar->add_menu( array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-settings',
		'title'  => __( 'Settings', 'secupress' ),
		'href'   => esc_url( secupress_admin_url( 'settings' ) ),
	) );
}
