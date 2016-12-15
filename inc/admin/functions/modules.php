<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Activate a sub-module.
 *
 * @since 1.0
 *
 * @param (string) $module                  The module.
 * @param (string) $submodule               The sub-module.
 * @param (array)  $incompatible_submodules An array of sub-modules to deactivate.
 *
 * @return (bool) True on success. False on failure or if the submodule was already active.
 */
function secupress_activate_submodule( $module, $submodule, $incompatible_submodules = array() ) {
	$file_path = secupress_get_submodule_file_path( $module, $submodule );

	if ( ! $file_path ) {
		return false;
	}

	$is_active = secupress_is_submodule_active( $module, $submodule );
	$submodule = sanitize_key( $submodule );

	if ( ! $is_active ) {
		// Activate the sub-module.
		if ( ! empty( $incompatible_submodules ) ) {
			// Deactivate incompatible sub-modules.
			secupress_deactivate_submodule( $module, $incompatible_submodules );
		}

		update_site_option( 'secupress_active_submodule_' . $submodule, $module );

		require_once( $file_path );

		secupress_add_module_notice( $module, $submodule, 'activation' );
	}

	/**
	 * Fires once a sub-module is activated, even if it was already active.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $is_active True if the sub-module was already active.
	 */
	do_action( 'secupress.modules.activate_submodule_' . $submodule, $is_active );

	/**
	 * Fires once any sub-module is activated, even if it was already active.
	 *
	 * @since 1.0
	 *
	 * @param (string) $submodule The sub-module slug.
	 * @param (bool)   $is_active True if the sub-module was already active.
	 */
	do_action( 'secupress.modules.activate_submodule', $submodule, $is_active );

	if ( ! $is_active ) {
		secupress_delete_site_transient( SECUPRESS_ACTIVE_SUBMODULES );
	}

	return ! $is_active;
}


/**
 * Deactivate a sub-module.
 *
 * @since 1.0
 *
 * @param (string)       $module     The module.
 * @param (string|array) $submodules The sub-module. Can be an array, deactivate multiple sub-modules.
 * @param (array)        $args       An array of arguments to pass to the hooks.
 */
function secupress_deactivate_submodule( $module, $submodules, $args = array() ) {
	$submodules = (array) $submodules;

	if ( ! $submodules ) {
		return;
	}

	$delete_cache = false;

	foreach ( $submodules as $submodule ) {
		$is_inactive = ! secupress_is_submodule_active( $module, $submodule );
		$submodule   = sanitize_key( $submodule );

		if ( ! $is_inactive ) {
			// Deactivate the sub-module.
			delete_site_option( 'secupress_active_submodule_' . $submodule );
			$delete_cache = true;

			secupress_add_module_notice( $module, $submodule, 'deactivation' );
		}

		/**
		 * Fires once a sub-module is deactivated.
		 *
		 * @since 1.0
		 *
		 * @param (array) $args        Some arguments.
		 * @param (bool)  $is_inactive True if the sub-module was already inactive.
		 */
		do_action( 'secupress.modules.deactivate_submodule_' . $submodule, $args, $is_inactive );

		/**
		 * Fires once any sub-module is deactivated.
		 *
		 * @since 1.0
		 *
		 * @param (string) $submodule   The sub-module slug.
		 * @param (array)  $args        Some arguments.
		 * @param (bool)   $is_inactive True if the sub-module was already inactive.
		 */
		do_action( 'secupress.modules.deactivate_submodule', $submodule, $args, $is_inactive );
	}

	if ( $delete_cache ) {
		secupress_delete_site_transient( SECUPRESS_ACTIVE_SUBMODULES );
	}
}


/**
 * Activate a sub-module silently. This will remove a previous activation notice and trigger no activation hook.
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 */
function secupress_activate_submodule_silently( $module, $submodule ) {
	$file_path = secupress_get_submodule_file_path( $module, $submodule );

	if ( ! $file_path ) {
		return;
	}

	// Remove deactivation notice.
	secupress_remove_module_notice( $module, $submodule, 'deactivation' );

	if ( secupress_is_submodule_active( $module, $submodule ) ) {
		return;
	}

	$submodule = sanitize_key( $submodule );

	// Activate the submodule.
	update_site_option( 'secupress_active_submodule_' . $submodule, $module );

	require_once( $file_path );

	secupress_delete_site_transient( SECUPRESS_ACTIVE_SUBMODULES );
}


/**
 * Deactivate a sub-module silently. This will remove all previous activation notices and trigger no deactivation hook.
 *
 * @since 1.0
 *
 * @param (string)       $module     The module.
 * @param (string|array) $submodules The sub-module. Can be an array, deactivate multiple sub-modules.
 * @param (array)        $args       An array of arguments to pass to the hooks.
 */
function secupress_deactivate_submodule_silently( $module, $submodules, $args = array() ) {
	$submodules = (array) $submodules;

	if ( ! $submodules ) {
		return;
	}

	$delete_cache = false;

	foreach ( $submodules as $submodule ) {
		// Remove activation notice.
		secupress_remove_module_notice( $module, $submodule, 'activation' );

		if ( ! secupress_is_submodule_active( $module, $submodule ) ) {
			continue;
		}

		// Deactivate the submodule.
		delete_site_option( 'secupress_active_submodule_' . $submodule );
		$delete_cache = true;
	}

	if ( $delete_cache ) {
		secupress_delete_site_transient( SECUPRESS_ACTIVE_SUBMODULES );
	}
}


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
 * Add a sub-module (de)activation notice.
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 * @param (string) $action    "activation" or "deactivation".
 */
function secupress_add_module_notice( $module, $submodule, $action ) {
	$submodule_name = secupress_get_module_data( $module, $submodule );

	if ( empty( $submodule_name['Name'] ) ) {
		return;
	}

	$submodule_name    = $submodule_name['Name'];
	$transient_name    = 'secupress_module_' . $action . '_' . get_current_user_id();
	$transient_value   = secupress_get_site_transient( $transient_name );
	$transient_value   = is_array( $transient_value ) ? $transient_value : array();
	$transient_value[] = $submodule_name;

	secupress_set_site_transient( $transient_name, $transient_value );

	/**
	 * Fires once a sub-module (de)activation notice is created.
	 * The dynamic part of this hook name is "activation" or "deactivation".
	 *
	 * @since 1.0
	 *
	 * @param (string) $module    The module.
	 * @param (string) $submodule The sub-module slug.
	 */
	do_action( 'secupress.modules.notice_' . $action, $module, $submodule );
}


/**
 * Remove a sub-module (de)activation notice.
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 * @param (string) $action    "activation" or "deactivation".
 */
function secupress_remove_module_notice( $module, $submodule, $action ) {
	$transient_name  = 'secupress_module_' . $action . '_' . get_current_user_id();
	$transient_value = secupress_get_site_transient( $transient_name );

	if ( ! $transient_value || ! is_array( $transient_value ) ) {
		return;
	}

	$submodule_name = secupress_get_module_data( $module, $submodule );

	if ( empty( $submodule_name['Name'] ) ) {
		return;
	}

	$transient_value = array_flip( $transient_value );
	$submodule_name  = $submodule_name['Name'];

	if ( ! isset( $transient_value[ $submodule_name ] ) ) {
		return;
	}

	unset( $transient_value[ $submodule_name ] );

	if ( $transient_value ) {
		$transient_value = array_flip( $transient_value );
		secupress_set_site_transient( $transient_name, $transient_value );
	} else {
		secupress_delete_site_transient( $transient_name );
	}
}


/**
 * Get a sub-module data (name, parent module, version, description, author).
 *
 * @since 1.0
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 *
 * @return (array)
 */
function secupress_get_module_data( $module, $submodule ) {
	$default_headers = array(
		'Name'        => 'Module Name',
		'Module'      => 'Main Module',
		'Version'     => 'Version',
		'Description' => 'Description',
		'Author'      => 'Author',
	);

	$file_path = secupress_get_submodule_file_path( $module, $submodule );

	if ( $file_path ) {
		return get_file_data( $file_path, $default_headers, 'module' );
	}

	return array();
}


/**
 * Remove (rewrite) rules from the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx systems or if the file is not writable.
 * This is usually used on the module deactivation.
 *
 * @since 1.0
 *
 * @param (string) $marker      Marker used in "BEGIN SecuPress ***".
 * @param (string) $module_name The module name.
 *
 * @return (bool) True if the file has been edited.
 */
function secupress_remove_module_rules_or_notice( $marker, $module_name ) {
	global $is_apache, $is_nginx, $is_iis7;

	// Apache.
	if ( $is_apache && ! secupress_write_htaccess( $marker ) ) {
		$message  = sprintf( __( '%s:', 'secupress' ), $module_name ) . ' ';
		$message .= sprintf(
			/** Translators: 1 is a file name, 2 and 3 are small parts of code. */
			__( 'Your %1$s file is not writable, you have to edit it manually. Please remove the rules between %2$s and %3$s from the %1$s file.', 'secupress' ),
			'<code>.htaccess</code>',
			"<code># BEGIN SecuPress $marker</code>",
			'<code># END SecuPress</code>'
		);
		add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
		return false;
	}

	// IIS7.
	if ( $is_iis7 && ! secupress_insert_iis7_nodes( $marker ) ) {
		$message  = sprintf( __( '%s:', 'secupress' ), $module_name ) . ' ';
		$message .= sprintf(
			/** Translators: 1 is a file name, 2 is a small part of code. */
			__( 'Your %1$s file is not writable, you have to edit it manually. Please remove the rules with %2$s from the %1$s file.', 'secupress' ),
			'<code>web.config</code>',
			"<code>SecuPress $marker</code>"
		);
		add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		return false;
	}

	// Nginx.
	if ( $is_nginx ) {
		$message  = sprintf( __( '%s:', 'secupress' ), $module_name ) . ' ';
		$message .= sprintf(
			/** Translators: 1 and 2 are small parts of code, 3 is a file name. */
			__( 'Your server runs <strong>Ngnix</strong>. You have to edit the configuration file manually. Please remove all rules between %1$s and %2$s from the %3$s file.', 'secupress' ),
			"<code># BEGIN SecuPress $marker</code>",
			'<code># END SecuPress</code>',
			'<code>nginx.conf</code>'
		);
		add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
		return false;
	}

	return true;
}


/**
 * Add (rewrite) rules to the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx or not supported systems, or if the file is not writable.
 * This is usually used on the module activation.
 *
 * @since 1.0
 *
 * @param (array) $args An array of arguments.
 *
 * @return (bool) True if the file has been edited.
 */
function secupress_add_module_rules_or_notice( $args ) {
	global $is_apache, $is_nginx, $is_iis7;

	$args = array_merge( array(
		'rules'    => '',
		'marker'   => '',
		'iis_args' => array(),
		'title'    => '', // Submodule name.
	), $args );

	$rules    = $args['rules'];
	$marker   = $args['marker'];
	$iis_args = $args['iis_args'];
	$title    = $args['title'];

	// Apache.
	if ( $is_apache ) {
		// Write in `.htaccess` file.
		if ( ! secupress_write_htaccess( $marker, $rules ) ) {
			// File not writable.
			$rules    = esc_html( $rules );
			$message  = sprintf( __( '%s:', 'secupress' ), $title ) . ' ';
			$message .= sprintf(
				/** Translators: 1 is a file name, 2 is some code. */
				__( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
				'<code>.htaccess</code>',
				"<pre># BEGIN SecuPress $marker\n$rules# END SecuPress</pre>"
			);
			add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
			return false;
		}

		return true;
	}

	// IIS7.
	if ( $is_iis7 ) {
		$iis_args['nodes_string'] = $rules;

		// Write in `web.config` file.
		if ( ! secupress_insert_iis7_nodes( $marker, $iis_args ) ) {
			// File not writable.
			$path     = ! empty( $iis_args['path'] ) ? $iis_args['path'] : '';
			$path_end = ! $path && strpos( ltrim( $rules ), '<rule ' ) === 0 ? '/rewrite/rules' : '';
			$path     = '/configuration/system.webServer' . ( $path ? '/' . trim( $path, '/' ) : '' ) . $path_end;
			$spaces   = explode( '/', trim( $path, '/' ) );
			$spaces   = count( $spaces ) - 1;
			$spaces   = str_repeat( ' ', $spaces * 2 );
			$rules    = esc_html( $rules );
			$message  = sprintf( __( '%s:', 'secupress' ), $title ) . ' ';

			if ( ! empty( $iis_args['node_types'] ) ) {
				$message .= sprintf(
					/** Translators: 1 is a file name, 2 is a tag name, 3 is a folder path (kind of), 4 is some code. */
					__( 'Your %1$s file is not writable. Please remove any previous %2$s tag and add the following lines inside the tags hierarchy %3$s (create it if does not exist): %4$s', 'secupress' ),
					'<code>web.config</code>',
					'<code class="secupress-iis7-node-type">' . $iis_args['node_types'] . '</code>',
					'<code class="secupress-iis7-path">' . $path . '</code>',
					"<pre>{$spaces}{$rules}</pre>"
				);
			} else {
				$message .= sprintf(
					/** Translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code. */
					__( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ),
					'<code>web.config</code>',
					'<code class="secupress-iis7-path">' . $path . '</code>',
					"<pre>{$spaces}{$rules}</pre>"
				);
			}
			add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
			return false;
		}

		return true;
	}

	// Nginx.
	if ( $is_nginx ) {
		// We can't edit the file, so we'll tell the user how to do.
		$message  = sprintf( __( '%s:', 'secupress' ), $title ) . ' ';
		$message .= sprintf(
			/** Translators: 1 is a file name, 2 is some code */
			__( 'Your server runs <strong>Ngnix</strong>. You have to edit the configuration file manually. Please add the following code to your %1$s file: %2$s', 'secupress' ),
			'<code>nginx.conf</code>',
			"<pre>$rules</pre>"
		);
		add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
		return false;
	}

	// Server not supported.
	$message  = sprintf( __( '%s:', 'secupress' ), $title ) . ' ';
	$message .= __( 'It seems your server does not use <strong>Apache</strong>, <strong>Ngnix</strong>, nor <strong>IIS7</strong>. This module won\'t work.', 'secupress' );
	add_settings_error( 'general', 'unknown_os', $message, 'error' );
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
