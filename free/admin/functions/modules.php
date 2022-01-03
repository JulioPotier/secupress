<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Depending on the value of `$activate`, will activate or deactivate a sub-module.
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 * @param (bool)   $activate  True to activate, false to deactivate.
 */
function secupress_manage_submodule( $module, $submodule, $activate ) {
	if ( $activate ) {
		secupress_activate_submodule( $module, $submodule );
	} else {
		secupress_deactivate_submodule( $module, $submodule );
	}
}


/**
 * This is used when submitting a module form.
 * If we submitted the given module form, it will return an array containing the values of sub-modules to activate.
 *
 * @since 1.0
 *
 * @param (string) $module The module.
 *
 * @return (array|bool) False if we're not submitting the module form. An array like `array( 'submodule1' => 1, 'submodule2' => 1 )` otherwise.
 */
function secupress_get_submodule_activations( $module ) {
	static $done = array();

	if ( isset( $done[ $module ] ) ) {
		return false;
	}

	$done[ $module ] = true;

	if ( isset( $_POST['option_page'] ) && 'secupress_' . $module . '_settings' === $_POST['option_page'] ) { // WPCS: CSRF ok.
		return isset( $_POST['secupress-plugin-activation'] ) && is_array( $_POST['secupress-plugin-activation'] ) ? $_POST['secupress-plugin-activation'] : array(); // WPCS: CSRF ok.
	}

	return false;
}


/**
 * Invert the roles values in settings.
 * Note: the "*_affected_role" options are misnamed, they should be called "*_excluded_roles", because we store roles that won't be affected.
 *
 * @since 1.0
 *
 * @param (array)  $settings The settings passed by reference.
 * @param (string) $module   The module.
 * @param (string) $plugin   The plugin.
 */
function secupress_manage_affected_roles( &$settings, $module, $plugin ) {
	static $roles;

	if ( ! isset( $roles ) ) {
		$roles = new WP_Roles();
		$roles = $roles->get_names();
		$roles = array_flip( $roles );
		$roles = array_combine( $roles, $roles );
	}

	if ( empty( $settings[ $plugin . '_affected_role' ]['witness'] ) ) {
		// Use old values, `$settings` does not come from our module page.
		$old_settings = get_site_option( "secupress_{$module}_settings" );

		if ( empty( $old_settings[ $plugin . '_affected_role' ] ) || ! is_array( $old_settings[ $plugin . '_affected_role' ] ) ) {
			// All roles.
			unset( $settings[ $plugin . '_affected_role' ] );
		} else {
			// Old roles that still exist.
			$settings[ $plugin . '_affected_role' ] = array_intersect( $roles, $old_settings[ $plugin . '_affected_role' ] );
		}
	} else {
		// Reverse submited values to store the excluded roles.
		if ( empty( $settings[ $plugin . '_affected_role' ] ) || ! is_array( $settings[ $plugin . '_affected_role' ] ) ) {
			// We won't allow to have no roles set, so we take them all.
			unset( $settings[ $plugin . '_affected_role' ] );
		} else {
			// Roles that are not selected.
			$settings[ $plugin . '_affected_role' ] = array_diff( $roles, $settings[ $plugin . '_affected_role' ] );
		}
	}

	// Useless, just to be sure.
	unset( $settings[ $plugin . '_affected_role' ]['witness'] );

	if ( empty( $settings[ $plugin . '_affected_role' ] ) || $roles === $settings[ $plugin . '_affected_role' ] ) {
		// We won't allow to have no roles set, so we take them all.
		unset( $settings[ $plugin . '_affected_role' ] );
	}
}


/**
 * Returns a i18n message used with a packed plugin activation checkbox to tell the user that the standalone plugin will be deactivated.
 *
 * @since 1.0
 *
 * @param (string) $plugin_basename The standalone plugin basename.
 *
 * @return (string|null) Return null if the plugin is not activated.
 */
function secupress_get_deactivate_plugin_string( $plugin_basename ) {
	if ( ! is_plugin_active( $plugin_basename ) ) {
		return null;
	}

	$plugin_basename = path_join( WP_PLUGIN_DIR, $plugin_basename );
	$plugin = get_plugin_data( $plugin_basename, false, false );

	return sprintf( __( 'will deactivate the plugin %s.', 'secupress' ), '<strong>' . $plugin['Name'] . '</strong>' );
}

/**
 * Returns a i18n message used with a packed plugin activation checkbox to tell the user that a plugin doing the same thing is already active
 *
 * @since 1.3.2
 *
 * @param (string) $plugin_basename The standalone plugin basename.
 * @param (string) $settings_page The possible setting page.
 *
 * @return (string|null) Return null if the plugin is not activated.
 */
function secupress_plugin_in_usage_string( $plugin_basename, $settings_page = '' ) {
	if ( ! is_plugin_active( $plugin_basename ) ) {
		return null;
	}

	$plugin_basename = path_join( WP_PLUGIN_DIR, $plugin_basename );
	$plugin = get_plugin_data( $plugin_basename, false, false );

	$content = sprintf( __( 'You can not use this feature now because you are using the plugin %s. Please deactivate it.', 'secupress' ), '<strong>' . esc_html( $plugin['Name'] ) . '</strong>' );
	if ( $settings_page ) {
		$content .= sprintf( '<br><a href="%s">' . __( 'Open the %s settings page', 'secupress' ) . '.</a>', esc_url( admin_url( $settings_page ) ), '<strong>' . esc_html( $plugin['Name'] ) . '</strong>' );
	}

	return $content;
}
