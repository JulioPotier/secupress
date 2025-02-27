<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ON MODULE SETTINGS SAVE ===================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Callback to filter, sanitize, validate and de/activate submodules.
 *
 * @since 1.0
 *
 * @param (array) $settings The module settings.
 *
 * @return (array) The sanitized and validated settings.
 */
function secupress_plugins_themes_settings_callback( $settings ) {
	$modulenow = 'plugins-themes';
	$activate  = secupress_get_submodule_activations( $modulenow );
	$settings  = $settings && is_array( $settings ) ? $settings : array();

	if ( isset( $settings['sanitized'] ) ) {
		return $settings;
	}
	$settings['sanitized'] = 1;

	/*
	 * Each submodule has its own sanitization function.
	 */

	// Plugins Page.
	secupress_plugins_settings_callback( $modulenow, $settings, $activate );

	// Themes Page.
	secupress_themes_settings_callback( $modulenow, $activate );

	// Uploads.
	secupress_uploads_settings_callback( $modulenow, $activate );



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


/**
 * Removed plugins.
 *
 * @since 1.0
 *
 * @param (string)     $modulenow Current module.
 * @param (array)      $settings  The module settings, passed by reference.
 * @param (bool|array) $activate  Used to (de)activate plugins.
 */
function secupress_plugins_settings_callback( $modulenow, &$settings, $activate ) {
	if ( false === $activate ) {
		return;
	}
	$db_opt          = secupress_get_module_option( 'plugins_confirm', false, $modulenow );
	$confirmed       = $db_opt || isset( $settings['plugins_confirm'] );
	$plugins_actions = isset( $activate['plugins_actions'] ) && $activate['plugins_actions'];

	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'plugin-installation', $confirmed && $plugins_actions ); // keep the name "plugin-installation", it's the file

	if ( isset( $settings['plugins_show-all-color'] ) ) {
		$settings['plugins_show-all-color'] = secupress_sanitize_hex_color( $settings['plugins_show-all-color'], '#FAC898' );
	} else {
		unset( $settings['plugins_show-all-color'] );
	}
	secupress_manage_submodule( $modulenow, 'plugin-show-all',     isset( $activate['plugins_show-all'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'detect-bad-plugins',  ! empty( $activate['plugins_detect_bad_plugins'] ) );
	}

	if ( ! secupress_is_submodule_active( $modulenow, 'plugin-installation' ) ) {
		unset( $settings['plugins_confirm'] );
	} else {
		$settings['plugins_confirm'] = 1;
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
function secupress_themes_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}
	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'theme-installation', isset( $activate['themes_actions'] ) );

	if ( secupress_is_pro() ) {
		secupress_manage_submodule( $modulenow, 'detect-bad-themes', ! empty( $activate['themes_detect_bad_themes'] ) );
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
function secupress_uploads_settings_callback( $modulenow, $activate ) {
	if ( false === $activate ) {
		return;
	}
	if ( isset( $_POST['reinstall-plugins'] ) ) {
		secupress_reinstall_plugins();
		return;
	}
	// (De)Activation.
	secupress_manage_submodule( $modulenow, 'uploads',   isset( $activate['uploads_activate'][0] ) && 'uploads'   === $activate['uploads_activate'][0] );
	secupress_manage_submodule( $modulenow, 'force-ftp', isset( $activate['uploads_activate'][0] ) && 'force-ftp' === $activate['uploads_activate'][0] );
}


/** --------------------------------------------------------------------------------------------- */
/** INSTALL/RESET =============================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.first_install', 'secupress_plugins_themes_module_activation' );
/**
 * On SecuPress first install, auto-activate "Detect Bad Plugins/Themes" submodules.
 *
 * @since 1.0
 *
 * @param (string) $module The module(s) that will be reset to default. `all` means "all modules".
 */
function secupress_plugins_themes_module_activation( $module ) {
	if ( 'all' === $module ) {
		secupress_activate_submodule_silently( 'plugins-themes', 'detect-bad-plugins' );
		secupress_activate_submodule_silently( 'plugins-themes', 'detect-bad-themes' );
	}
}
