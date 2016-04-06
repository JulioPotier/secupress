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
	$activate  = secupress_get_submodule_activations( $modulenow );

	/*
	 * Each submodule has its own sanitization function.
	 */

	// Plugins Page
	__secupress_plugins_settings_callback( $modulenow, $activate );

	// Themes Page
	__secupress_themes_settings_callback( $modulenow, $activate );

	// Uploads
	__secupress_uploads_settings_callback( $modulenow, $activate );

	// There are no settings to save.
	return array();
}


/**
 * Plugins plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_plugins_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'plugin-update',       ! empty( $activate['plugins_update'] ) );
	secupress_manage_submodule( $modulenow, 'plugin-installation', ! empty( $activate['plugins_installation'] ) );
	secupress_manage_submodule( $modulenow, 'detect-bad-plugins',  ! empty( $activate['plugins_detect_bad_plugins'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'plugin-activation',      ! empty( $activate['plugins_activation'] ) );
		secupress_manage_submodule( $modulenow, 'plugin-deactivation',    ! empty( $activate['plugins_deactivation'] ) );
		secupress_manage_submodule( $modulenow, 'plugin-deletion',        ! empty( $activate['plugins_deletion'] ) );
		secupress_manage_submodule( $modulenow, 'autoupdate-bad-plugins', ! empty( $activate['plugins_detect_bad_plugins'] ) && ! empty( $activate['plugins_autoupdate_bad_plugins'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'plugin-activation', 'plugin-deactivation', 'plugin-deletion', 'autoupdate-bad-plugins' ) );
	}
}


/**
 * Themes plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_themes_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'theme-update',       ! empty( $activate['themes_update'] ) );
	secupress_manage_submodule( $modulenow, 'theme-installation', ! empty( $activate['themes_installation'] ) );
	secupress_manage_submodule( $modulenow, 'detect-bad-themes',  ! empty( $activate['themes_detect_bad_themes'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'theme-activation',      ! empty( $activate['themes_activation'] ) );
		secupress_manage_submodule( $modulenow, 'theme-deletion',        ! empty( $activate['themes_deletion'] ) );
		secupress_manage_submodule( $modulenow, 'autoupdate-bad-themes', ! empty( $activate['themes_detect_bad_themes'] ) && ! empty( $activate['themes_autoupdate_bad_themes'] ) );
	} else {
		secupress_deactivate_submodule( $modulenow, array( 'theme-activation', 'theme-deletion', 'autoupdate-bad-themes' ) );
	}
}


/**
 * Uploads plugin.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function __secupress_uploads_settings_callback( $modulenow, $activate ) {
	if ( false !== $activate ) {
		// (De)Activation.
		secupress_manage_submodule( $modulenow, 'uploads', ! empty( $activate['uploads_activate'] ) );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* INSTALL/RESET ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

/**
 * On SecuPress first install, auto-activate "Detect Bad Plugins/Themes" submodules.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
add_action( 'wp_secupress_first_install', 'secupress_plugins_themes_module_activation' );

function secupress_plugins_themes_module_activation( $module ) {
	if ( 'all' === $module ) {
		secupress_activate_submodule( 'plugins-themes', 'detect-bad-plugins' );
		secupress_activate_submodule( 'plugins-themes', 'detect-bad-themes' );
	}
}
