<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.4 Free module
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_antispam_settings_callback( $settings ) {
	$modulenow = 'antispam';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// (De)Activation.
	if ( false !== $activate ) {
		$activate = isset( $activate['antispam_antispam'] ) && is_array( $activate['antispam_antispam'] ) ? array_flip( $activate['antispam_antispam'] ) : array();
		$activate = array_slice( $activate, 0, 1, true ); // Only one choice.

		secupress_manage_submodule( $modulenow, 'fightspam', isset( $activate['fightspam'] ) );
		secupress_manage_submodule( $modulenow, 'remove-comment-feature', isset( $activate['remove-comment-feature'] ) );
	}

	// Sanitization.
	$settings['antispam_mark-as']                  = ! empty( $settings['antispam_mark-as'] ) && 'trash' === $settings['antispam_mark-as'] ? 'trash' : 'spam';
	$settings['antispam_block-shortcodes']         = (int) ! empty( $settings['antispam_block-shortcodes'] );
	$settings['antispam_better-blacklist-comment'] = (int) ! empty( $settings['antispam_better-blacklist-comment'] );
	$settings['antispam_forbid-pings-trackbacks']  = (int) ! empty( $settings['antispam_forbid-pings-trackbacks'] );
	$settings['antispam_comment-delay']            = (int) ! empty( $settings['antispam_comment-delay'] );

	/**
	 * Filter the settings before saving.
	 *
	 * @since 1.4.9
	 *
	 * @param (array)      $settings The module settings.
	 * @param (array\bool) $activate Contains the activation rules for the different modules
	 */
	$settings = apply_filters( "secupress_{$modulenow}_settings_callback", $settings, $activate );

	return $settings;
}


/** --------------------------------------------------------------------------------------------- */
/** NOTICES ===================================================================================== */
/** ----------------------------------------------------------------------------------------------*/

add_filter( 'secupress.plugins.packed-plugins', 'secupress_remove_comment_feature_add_packed_plugin' );
/**
 * Display a notice if the standalone version of Remove Comment Feature is used.
 *
 * @since 1.0
 *
 * @param (array) $plugins A list of plugin paths, relative to the plugins folder.
 *
 * @return (array)
 */
function secupress_remove_comment_feature_add_packed_plugin( $plugins ) {
	$plugins['remove-comment-feature'] = 'no-comment/no-comment.php';
	return $plugins;
}


/** --------------------------------------------------------------------------------------------- */
/** INSTALL/RESET =============================================================================== */
/** ----------------------------------------------------------------------------------------------*/

add_action( 'secupress.first_install', 'secupress_install_antispam_module' );
/**
 * Create default option on install and reset.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_install_antispam_module( $module ) {
	// First install or reset.
	if ( 'all' === $module || 'antispam' === $module ) {
		update_site_option( 'secupress_antispam_settings', array(
			'antispam_mark-as'                  => 'trash',
			'antispam_block-shortcodes'         => 1,
			'antispam_better-blacklist-comment' => 1,
		) );
	}
}
