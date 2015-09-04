<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Add menu in admin bar
 * From this menu, you can preload the cache files, clear entire domain cache or post cache (front & back-end)
 *
 * @since 1.0
 */
add_action( 'admin_bar_menu', 'secupress_admin_bar', PHP_INT_MAX );
function secupress_admin_bar( $wp_admin_bar )
{
	if ( ! current_user_can( apply_filters( 'secupress_capacity', 'administrator', 'adminbar' ) ) )  {
		return;
	}

	$action = 'purge_cache';
	// Parent
    $wp_admin_bar->add_menu( array(
	    'id'    => 'secupress',
	    'title' => SECUPRESS_PLUGIN_NAME,
	    'href'  => secupress_admin_url( 'dashboard' ),
	));

	// Settings
	$wp_admin_bar->add_menu(array(
		'parent' => 'secupress',
		'id' 	 => 'secupress-dashboard',
		'title'  => __( 'Dashboard' ),
	    'href'   => secupress_admin_url( 'dashboard' ),
	));

}
