<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* ON MODULE SETTINGS SAVE ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function __secupress_plugins_themes_settings_callback( $settings ) {
	$modulenow = 'plugins-themes';
	$settings  = $settings ? $settings : array();

	/*
	 * Each submodule has its own sanitization function.
	 * The `$settings` parameter is passed by reference.
	 */

	// Plugins Page
	__secupress_plugins_page_settings_callback( $modulenow, $settings );

	// Themes Page
	__secupress_themes_page_settings_callback( $modulenow, $settings );

	return $settings;
}


/**
 * (De)Activate Plugins Page plugins.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_plugins_page_settings_callback( $modulenow, &$settings ) {
	secupress_manage_submodule( $modulenow, 'plugin-update',       ! empty( $settings['plugins_update'] ) );
	secupress_manage_submodule( $modulenow, 'plugin-installation', ! empty( $settings['plugins_installation'] ) );
	secupress_manage_submodule( $modulenow, 'detect-bad-plugins',  ! empty( $settings['plugins_detect_bad_plugins'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'plugin-activation',      ! empty( $settings['plugins_activation'] ) );
		secupress_manage_submodule( $modulenow, 'plugin-deactivation',    ! empty( $settings['plugins_deactivation'] ) );
		secupress_manage_submodule( $modulenow, 'plugin-deletion',        ! empty( $settings['plugins_deletion'] ) );
		secupress_manage_submodule( $modulenow, 'autoupdate-bad-plugins', ! empty( $settings['plugins_detect_bad_plugins'] ) && ! empty( $settings['plugins_autoupdate_bad_plugins'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'plugin-activation', 'plugin-deactivation', 'plugin-deletion', 'autoupdate-bad-plugins' ) );
	}

	unset(
		$settings['plugins_update'],
		$settings['plugins_installation'],
		$settings['plugins_detect_bad_plugins'],
		$settings['plugins_activation'],
		$settings['plugins_deactivation'],
		$settings['plugins_deletion'],
		$settings['plugins_autoupdate_bad_plugins']
	);
}


/**
 * (De)Activate Themes Page plugins.
 *
 * @since 1.0
 *
 * @param (string) $modulenow Current module.
 * @param (array)  $settings  The module settings, passed by reference.
 */
function __secupress_themes_page_settings_callback( $modulenow, &$settings ) {
	secupress_manage_submodule( $modulenow, 'theme-update',       ! empty( $settings['themes_update'] ) );
	secupress_manage_submodule( $modulenow, 'theme-installation', ! empty( $settings['themes_installation'] ) );
	secupress_manage_submodule( $modulenow, 'detect-bad-themes',  ! empty( $settings['themes_detect_bad_themes'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'theme-activation',      ! empty( $settings['themes_activation'] ) );
		secupress_manage_submodule( $modulenow, 'theme-deletion',        ! empty( $settings['themes_deletion'] ) );
		secupress_manage_submodule( $modulenow, 'autoupdate-bad-themes', ! empty( $settings['themes_detect_bad_themes'] ) && ! empty( $settings['themes_autoupdate_bad_themes'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'theme-activation', 'theme-deletion', 'autoupdate-bad-themes' ) );
	}

	unset(
		$settings['themes_update'],
		$settings['themes_installation'],
		$settings['themes_detect_bad_themes'],
		$settings['themes_activation'],
		$settings['themes_deletion'],
		$settings['themes_autoupdate_bad_themes']
	);
}
