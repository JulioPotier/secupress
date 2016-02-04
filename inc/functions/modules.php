<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


function secupress_deactivate_submodule( $module, $plugins, $args = array() ) {
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( ! is_array( $plugins ) ) {
		$plugins = (array) $plugins;
	}

	foreach ( $plugins as $plugin ) {
		$plugin_file = sanitize_key( $plugin );

		if ( ! $active_plugins || ! isset( $active_plugins[ $module ] ) || ! in_array_deep( $plugin_file, $active_plugins ) ) {
			continue;
		}

		$key = array_search( $plugin_file, $active_plugins[ $module ] );

		if ( false === $key ) {
			continue;
		}

		unset( $active_plugins[ $module ][ $key ] );

		if ( ! $active_plugins[ $module ] ) {
			unset( $active_plugins[ $module ] );
		}

		update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
		secupress_add_module_notice( $module, $plugin_file, 'deactivation' );

		do_action( 'secupress_deactivate_plugin_' . $plugin_file, $args );

		do_action( 'secupress_deactivate_plugin', $plugin_file, $args );
	}
}


function secupress_activate_submodule( $module, $plugin, $incompatibles_modules = array() ) { //// add the possiblity to activate it in "silent mode" (from a scanner fix and not from a user checkbox)?
	$plugin_file    = sanitize_key( $plugin );
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
	$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();
	$file_path      = SECUPRESS_MODULES_PATH . $module . '/plugins/' . $plugin_file . '.php';

	if ( ! file_exists( $file_path ) ) {
		return false;
	}

	if ( ! in_array_deep( $plugin_file, $active_plugins ) ) {
		if ( ! empty( $incompatibles_modules ) ) {
			secupress_deactivate_submodule( $module, $incompatibles_modules );

			$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
			$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();
		}

		$active_plugins[ $module ]   = isset( $active_plugins[ $module ] ) ? $active_plugins[ $module ] : array();
		$active_plugins[ $module ][] = $plugin_file;

		update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
		require_once( $file_path );
		secupress_add_module_notice( $module, $plugin_file, 'activation' );

		do_action( 'secupress_activate_plugin_' . $plugin_file );

		do_action( 'secupress_activate_plugin', $plugin_file );

		return true;
	}

	return false;
}


function secupress_manage_submodule( $module, $plugin, $activate ) {
	if ( $activate ) {
		secupress_activate_submodule( $module, $plugin );
	} else {
		secupress_deactivate_submodule( $module, $plugin );
	}
}


function secupress_get_submodule_activations( $module ) {
	static $done = array();

	if ( isset( $done[ $module ] ) ) {
		return false;
	}

	$done[ $module ] = true;

	if ( isset( $_POST['option_page'] ) && 'secupress_' . $module . '_settings' === $_POST['option_page'] ) {
		return isset( $_POST['secupress-plugin-activation'] ) && is_array( $_POST['secupress-plugin-activation'] ) ? $_POST['secupress-plugin-activation'] : array();
	}

	return false;
}


function secupress_add_module_notice( $module, $submodule, $action ) {
	global $current_user;

	$transient_name = "secupress_module_{$action}_{$current_user->ID}";
	$current        = get_site_transient( $transient_name );
	$submodule_data = secupress_get_module_data( $module , $submodule );
	$current[]      = $submodule_data['Name'];

	set_site_transient( $transient_name, $current );

	do_action( 'module_notice_' . $action, $module, $submodule );
}


function secupress_get_module_data( $module, $submodule ) {
	$default_headers = array(
		'Name'        => 'Module Name',
		'Module'      => 'Main Module',
		'Version'     => 'Version',
		'Description' => 'Description',
		'Author'      => 'Author',
	);

	$file = SECUPRESS_MODULES_PATH . $module . '/plugins/' . $submodule . '.php';

	if ( file_exists( $file ) ) {
		return get_file_data( $file, $default_headers, 'module' );
	}

	return array();
}
