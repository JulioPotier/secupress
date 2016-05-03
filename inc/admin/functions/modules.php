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
 * @return (bool) True on success. False on failure.
 */
function secupress_activate_submodule( $module, $submodule, $incompatible_submodules = array() ) {
	$file_path = secupress_get_submodule_file_path( $module, $submodule );

	if ( ! $file_path ) {
		return false;
	}

	$submodule_slug = sanitize_key( $submodule );
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
	$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();

	if ( secupress_in_array_deep( $submodule_slug, $active_plugins ) ) {
		return false;
	}

	if ( ! empty( $incompatible_submodules ) ) {
		secupress_deactivate_submodule( $module, $incompatible_submodules );

		$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
		$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();
	}

	$active_plugins[ $module ]   = isset( $active_plugins[ $module ] ) ? $active_plugins[ $module ] : array();
	$active_plugins[ $module ][] = $submodule_slug;

	update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );

	require_once( $file_path );

	secupress_add_module_notice( $module, $submodule_slug, 'activation' );

	/**
	 * Fires once a sub-module is activated.
	 *
	 * @since 1.0
	 */
	do_action( 'secupress.modules.activate_submodule_' . $submodule_slug );

	/**
	 * Fires once any sub-module is activated.
	 *
	 * @since 1.0
	 *
	 * @param (string) $submodule_slug The submodule slug.
	 */
	do_action( 'secupress.modules.activate_submodule', $submodule_slug );

	return true;
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
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( ! $active_plugins ) {
		return;
	}

	$submodules = (array) $submodules;

	foreach ( $submodules as $submodule ) {
		$submodule_slug = sanitize_key( $submodule );

		if ( ! isset( $active_plugins[ $module ] ) || ! secupress_in_array_deep( $submodule_slug, $active_plugins ) ) {
			continue;
		}

		$key = array_search( $submodule_slug, $active_plugins[ $module ] );

		if ( false === $key ) {
			continue;
		}

		unset( $active_plugins[ $module ][ $key ] );

		if ( ! $active_plugins[ $module ] ) {
			unset( $active_plugins[ $module ] );
		}

		update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );

		secupress_add_module_notice( $module, $submodule_slug, 'deactivation' );

		/**
		 * Fires once a sub-module is deactivated.
		 *
		 * @since 1.0
		 *
		 * @param (array) $args Some arguments.
		 */
		do_action( 'secupress.modules.deactivate_submodule_' . $submodule_slug, $args );

		/**
		 * Fires once any sub-module is deactivated.
		 *
		 * @since 1.0
		 *
		 * @param (string) $submodule_slug The submodule slug.
		 * @param (array)  $args           Some arguments.
		 */
		do_action( 'secupress.modules.deactivate_submodule', $submodule_slug, $args );
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

	$submodule_slug = sanitize_key( $submodule );
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );
	$active_plugins = is_array( $active_plugins ) ? $active_plugins : array();

	if ( secupress_in_array_deep( $submodule_slug, $active_plugins ) ) {
		return;
	}

	// Activate the submodule.
	$active_plugins[ $module ]   = isset( $active_plugins[ $module ] ) ? $active_plugins[ $module ] : array();
	$active_plugins[ $module ][] = $submodule_slug;

	update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );

	require_once( $file_path );
}


/**
 * Deactivate a sub-module silently. This will remove all previous activation noticel and trigger no deactivation hook.
 *
 * @since 1.0
 *
 * @param (string)       $module     The module.
 * @param (string|array) $submodules The sub-module. Can be an array, deactivate multiple sub-modules.
 * @param (array)        $args       An array of arguments to pass to the hooks.
 */
function secupress_deactivate_submodule_silently( $module, $submodules, $args = array() ) {
	$active_plugins = get_site_option( SECUPRESS_ACTIVE_SUBMODULES );

	if ( ! $active_plugins ) {
		return;
	}

	$submodules = (array) $submodules;

	foreach ( $submodules as $submodule ) {
		// Remove activation notice.
		secupress_remove_module_notice( $module, $submodule, 'activation' );

		// Deactivate the submodule.
		$submodule_slug = sanitize_key( $submodule );

		if ( ! isset( $active_plugins[ $module ] ) || ! secupress_in_array_deep( $submodule_slug, $active_plugins ) ) {
			continue;
		}

		$key = array_search( $submodule_slug, $active_plugins[ $module ] );

		if ( false === $key ) {
			continue;
		}

		unset( $active_plugins[ $module ][ $key ] );

		if ( ! $active_plugins[ $module ] ) {
			unset( $active_plugins[ $module ] );
		}
	}

	update_site_option( SECUPRESS_ACTIVE_SUBMODULES, $active_plugins );
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
	$submodule_name    = secupress_get_module_data( $module, $submodule );
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
	$submodule_name  = secupress_get_module_data( $module, $submodule );
	$submodule_name  = $submodule_name['Name'];
	$transient_name  = 'secupress_module_' . $action . '_' . get_current_user_id();
	$transient_value = secupress_get_site_transient( $transient_name );

	if ( ! $transient_value || ! is_array( $transient_value ) ) {
		return;
	}

	$transient_value = array_flip( $transient_value );

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
		$message  = sprintf( __( '%s: ', 'secupress' ), $module_name );
		$message .= sprintf(
			/* translators: 1 is a file name, 2 and 3 are small parts of code. */
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
		$message  = sprintf( __( '%s: ', 'secupress' ), $module_name );
		$message .= sprintf(
			/* translators: 1 is a file name, 2 is a small part of code. */
			__( 'Your %1$s file is not writable, you have to edit it manually. Please remove the rules with %2$s from the %1$s file.', 'secupress' ),
			'<code>web.config</code>',
			"<code>SecuPress $marker</code>"
		);
		add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
		return false;
	}

	// Nginx.
	if ( $is_nginx ) {
		$message  = sprintf( __( '%s: ', 'secupress' ), $module_name );
		$message .= sprintf(
			/* translators: 1 is a file name, 2 and 3 are small parts of code. */
			__( 'Your server uses a <i>Nginx</i> system, you have to edit the configuration file manually. Please remove the rules between %2$s and %3$s from the %1$s file.', 'secupress' ),
			'<code>nginx.conf</code>',
			"<code># BEGIN SecuPress $marker</code>",
			'<code># END SecuPress</code>'
		);
		add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
		return false;
	}

	return true;
}


/**
 * Add (rewrite) rules to the `.htaccess`/`web.config` file.
 * An error notice is displayed on nginx or not supported systems, or if the file is not writable. It will also deactivate the submodule silently if there is an error.
 * This is usually used on the module activation.
 *
 * @since 1.0
 *
 * @param (array) $args An array of arguments.
 *
 * @return (bool) True if the file has been edited.
 */
function secupress_add_module_rules_or_notice_and_deactivate( $args ) {
	global $is_apache, $is_nginx, $is_iis7;

	$args = array_merge( array(
		'rules'     => '',
		'marker'    => '',
		'iis_args'  => array(),
		'module'    => '',
		'submodule' => '',
		'title'     => '', // Submodule name.
	), $args );

	$rules     = $args['rules'];
	$marker    = $args['marker'];
	$iis_args  = $args['iis_args'];
	$module    = $args['module'];
	$submodule = $args['submodule'];
	$title     = $args['title'];

	// Apache.
	if ( $is_apache ) {
		// Write in `.htaccess` file.
		if ( ! secupress_write_htaccess( $marker, $rules ) ) {
			// File not writable.
			$rules    = esc_html( $rules );
			$message  = sprintf( __( '%s: ', 'secupress' ), $title );
			$message .= sprintf(
				/* translators: 1 is a file name, 2 is some code */
				__( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
				'<code>.htaccess</code>',
				"<pre># BEGIN SecuPress $marker\n$rules# END SecuPress</pre>"
			);
			add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );

			secupress_deactivate_submodule_silently( $module, $submodule );
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
			$message  = sprintf( __( '%s: ', 'secupress' ), $title );

			if ( ! empty( $iis_args['node_types'] ) ) {
				$message .= sprintf(
					/* translators: 1 is a file name, 2 is a tag name, 3 is a folder path (kind of), 4 is some code */
					__( 'Your %1$s file is not writable. Please remove any previous %2$s tag and add the following lines inside the tags hierarchy %3$s (create it if does not exist): %4$s', 'secupress' ),
					'<code>web.config</code>',
					'<code>' . $iis_args['node_types'] . '</code>',
					$path,
					"<pre>{$spaces}{$rules}</pre>"
				);
			} else {
				$message .= sprintf(
					/* translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code */
					__( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ),
					'<code>web.config</code>',
					$path,
					"<pre>{$spaces}{$rules}</pre>"
				);
			}
			add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );

			secupress_deactivate_submodule_silently( $module, $submodule );
			return false;
		}

		return true;
	}

	// Nginx.
	if ( $is_nginx ) {
		// We can't edit the file, so we'll tell the user how to do.
		$message  = sprintf( __( '%s: ', 'secupress' ), $title );
		$message .= sprintf(
			/* translators: 1 is a file name, 2 is some code */
			__( 'Your server uses a <i>Nginx</i> system, you have to edit the configuration file manually. Please add the following code into your %1$s file: %2$s', 'secupress' ),
			'<code>nginx.conf</code>',
			"<pre>$rules</pre>"
		);
		add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
		return true;
	}

	// Server not supported.
	$message  = sprintf( __( '%s: ', 'secupress' ), $title );
	$message .= __( 'It seems your server does not use <i>Apache</i>, <i>Nginx</i>, nor <i>IIS7</i>. This module won\'t work.', 'secupress' );
	add_settings_error( 'general', 'unknown_os', $message, 'error' );

	secupress_deactivate_submodule_silently( $module, $submodule );
	return false;
}


/**
 * Invert the roles values in settings.
 *
 * @since 1.0
 *
 * @param (array)  $settings The settings passed by reference.
 * @param (string) $plugin   The plugin.
 */
function secupress_manage_affected_roles( &$settings, $plugin ) {
	static $roles;

	if ( ! isset( $roles ) ) {
		$roles = new WP_Roles();
		$roles = $roles->get_names();
		$roles = array_flip( $roles );
		$roles = array_combine( $roles, $roles );
	}

	if ( empty( $settings[ $plugin . '_affected_role' ] ) || ! is_array( $settings[ $plugin . '_affected_role' ] ) ) {
		$settings[ $plugin . '_affected_role' ] = $roles;
	} else {
		$settings[ $plugin . '_affected_role' ] = array_diff( $roles, $settings[ $plugin . '_affected_role' ] );
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

	return sprintf( __( 'This will also deactivate the plugin %s.', 'secupress' ), '<strong>' . $plugin['Name'] . '</strong>' );
}