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
	$settings = $settings ? $settings : array();

	// Remove Comment Feature
	if ( isset( $settings['antispam_antispam'] ) && in_array( 'remove-comment-feature', $settings['antispam_antispam'] ) ) {
		secupress_activate_submodule( $modulenow, 'remove-comment-feature' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'remove-comment-feature' );
	}

	// Fight Spam
	if ( isset( $settings['antispam_antispam'] ) && in_array( 'fightspam', $settings['antispam_antispam'] ) ) {
		secupress_activate_submodule( $modulenow, 'fightspam' );
	} else {
		secupress_deactivate_submodule( $modulenow, 'fightspam' );
	}


	return $settings;
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

// Create default option on install.

// add_action( 'wp_secupress_first_install', '__secupress_install_antispam_module' ); 

function __secupress_install_antispam_module( $module ) {
	if ( 'all' === $module || 'antispam' === $module ) {
		$values = array(
			//// pas fini
		);
		secupress_update_module_options( $values, 'antispam' );
	}
}