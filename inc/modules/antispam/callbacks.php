<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize and de/activate submodules
 *
 * @since 1.0
 * @return array $settings
 */
function __secupress_antispam_settings_callback( $settings ) {
	$modulenow = 'antispam';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	// (De)Activation.
	if ( false !== $activate ) {
		$activate = isset( $activate['antispam_antispam'] ) && is_array( $activate['antispam_antispam'] ) ? array_flip( $activate['antispam_antispam'] ) : array();

		secupress_manage_submodule( $modulenow, 'fightspam', isset( $activate['fightspam'] ) );
		secupress_manage_submodule( $modulenow, 'remove-comment-feature', isset( $activate['remove-comment-feature'] ) );
	}

	// Sanitization.
	$settings['antispam_mark-as']                  = ! empty( $settings['antispam_mark-as'] ) && 'trash' === $settings['antispam_mark-as'] ? 'trash' : 'spam';
	$settings['antispam_block-shortcodes']         = (int) ! empty( $settings['antispam_block-shortcodes'] );
	$settings['antispam_better-blacklist-comment'] = (int) ! empty( $settings['antispam_better-blacklist-comment'] );
	$settings['antispam_forbid-pings-trackbacks']  = (int) ! empty( $settings['antispam_forbid-pings-trackbacks'] );

	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* NOTICES ====================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Display a notice if the standalone version of Remove Comment Feature is used.
 *
 * @since 1.0
 *
 * @param (array) $plugins A list of plugin paths, relative to the plugins folder.
 */
add_filter( 'secupress.plugins.packed-plugins', 'secupress_remove_comment_feature_add_packed_plugin' );

function secupress_remove_comment_feature_add_packed_plugin( $plugins ) {
	$plugins['remove-comment-feature'] = 'no-comment/no-comment.php';
	return $plugins;
}
