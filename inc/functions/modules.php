<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get modules title, icon, description and other informations.
 *
 * @since 1.0
 * @since 1.0.5 Includes information about numbers of free and pro options
 *
 * @return (array) All informations related to the modules.
 * @author Gregory Viguier (Geoffrey Crofte)
 */
function secupress_get_modules() {
	$should_be_pro = ! secupress_is_pro();

	$modules = array(
		'users-login'     => array(
			'title'       => __( 'Users &amp; Login', 'secupress' ),
			'icon'        => 'user-login',
			'summaries'   => array(
				'small'  => __( 'Protect your users', 'secupress' ),
				'normal' => __( 'The best and easiest way to make sure that users\' data will be protected, and their accounts not compromised.', 'secupress' ),
			),
			'description' => array(
				__( 'The best and easiest way to make sure that users\' data will be protected, and their accounts not compromised.', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 6,
				'pro_options'  => 5,
			),
		),
		'plugins-themes'  => array(
			'title'       => __( 'Plugins &amp; Themes', 'secupress' ),
			'icon'        => 'themes-plugins',
			'summaries'   => array(
				'small'  => __( 'Check your plugins &amp; themes', 'secupress' ),
				'normal' => __( 'Detect themes and plugins known as vulnerable to avoid hackings. Also, manage installation and activation rights on them.', 'secupress' ),
			),
			'description' => array(
				__( 'Detect themes and plugins known as vulnerable to avoid hackings. Also, manage installation and activation rights on them.', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 3,
				'pro_options'  => 7,
			),
		),
		'wordpress-core'  => array(
			'title'       => __( 'WordPress Core', 'secupress' ),
			'icon'        => 'core',
			'summaries'   => array(
				'small'  => __( 'Core Tweaking', 'secupress' ),
				'normal' => __( 'WordPress can be tweaked in so many ways. But are you using the right ones? Let\'s see!', 'secupress' ),
			),
			'description' => array(
				__( 'WordPress can be tweaked in so many ways. But are you using the right ones? Let\'s see!', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 5,
				'pro_options'  => 0,
			),
		),
		'sensitive-data'  => array(
			'title'       => __( 'Sensitive Data', 'secupress' ),
			'icon'        => 'sensitive-data',
			'summaries'   => array(
				'small'  => __( 'Keep your data safe', 'secupress' ),
				'normal' => __( 'Preserve your data and avoid losing your content in case of attack.', 'secupress' ),
			),
			'description' => array(
				__( 'Preserve your data and avoid losing your content in case of attack.', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 10,
				'pro_options'  => 3,
			),
		),
		'firewall'     => array(
			'title'       => __( 'Firewall', 'secupress' ),
			'icon'        => 'firewall',
			'summaries'   => array(
				'small'  => __( 'Block bad requests', 'secupress' ),
				'normal' => __( 'Malicious requests are common, unfortunatly. All malicious incoming requests will be checked and quietly blocked.', 'secupress' ),
			),
			'description' => array(
				__( 'Malicious requests are common, unfortunatly. All malicious incoming requests will be checked and quietly blocked.', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 4,
				'pro_options'  => 2,
			),
		),
		'file-system'     => array(
			'title'       => __( 'Malware Scan', 'secupress' ),
			'icon'        => 'file-system',
			'summaries'   => array(
				'small'  => __( 'Permissions &amp; Antivirus', 'secupress' ),
				'normal' => __( 'Check file permissions, run monitoring and antivirus on your installation to verify file integrity.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Check file permissions, run monitoring and antivirus on your installation to verify file integrity.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
			'counts' => array(
				'free_options' => 1,
				'pro_options'  => 2,
			),
		),
		'backups'         => array(
			'title'       => __( 'Backups', 'secupress' ),
			'icon'        => 'backups',
			'summaries'   => array(
				'small'  => __( 'Never lose anything', 'secupress' ),
				'normal' => __( 'Reduce the risks of losing your content in an attack by backing up your database and files.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Reduce the risks of losing your content in an attack by backing up your database and files.', 'secupress' ),
				sprintf( __( 'Don\'t forget to <a href="%s">schedule backups</a> as soon as possible.', 'secupress' ), esc_url( secupress_admin_url( 'modules', 'schedules' ) ) ),
			),
			'mark_as_pro' => $should_be_pro,
			'counts' => array(
				'free_options' => 0,
				'pro_options'  => 4,
			),
		),
		'antispam'        => array(
			'title'       => __( 'Anti Spam', 'secupress' ),
			'icon'        => 'antispam',
			'summaries'   => array(
				'small'  => __( 'Get rid of bad bots', 'secupress' ),
				'normal' => __( 'Traffic done by bot represents about 60% of the internet. Spams are done by these bots. Don\'t let them do that!', 'secupress' ),
			),
			'description' => array(
				__( 'Comments are great for your website, but bot traffic represents about 60 % of the internet. Spams are done by these bots, and they just want to add their content into your website. Don\'t let them do that!', 'secupress' ),
				sprintf( __( 'Do not forget to visit the <a href="%s">Settings &rsaquo; Discussion</a> area to add words to the blacklist and other usual settings regarding comments.', 'secupress' ), esc_url( admin_url( 'options-discussion.php' ) ) ),
				__( 'By default, identity theft is blocked, so if someone tries to comment using your email/name, the comment will be blocked.', 'secupress' ),
				__( 'Also by default, bad IPs are blocked, as are the author name, email and website url of known as spammer.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
			'counts' => array(
				'free_options' => 0,
				'pro_options'  => 7,
			),
		),
		'alerts'          => array(
			'title'       => __( 'Alerts', 'secupress' ),
			'icon'        => 'information',
			'summaries'   => array(
				'small'  => __( 'React quickly in case of attack', 'secupress' ),
				'normal' => __( 'Being alerted of some important events will help you to react quickly in case of possible attacks.', 'secupress' ),
			),
			'description' => array(
				__( 'Being alerted of some important events will help you to react quickly in case of possible attacks.', 'secupress' ),
			),
			'mark_as_pro' => $should_be_pro,
			'counts' => array(
				'free_options' => 0,
				'pro_options'  => 3,
			),
		),
		'schedules'       => array(
			'title'       => __( 'Schedules', 'secupress' ),
			'icon'        => 'schedule',
			'summaries'   => array(
				'small'  => __( 'Automate all your tasks', 'secupress' ),
				'normal' => sprintf( __( 'Let %s scan your website when you are away by using recurent scans.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'description' => array(
				sprintf( __( 'Let %s scan your website when you are away by using recurent scans.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'mark_as_pro' => $should_be_pro,
			'counts' => array(
				'free_options' => 0,
				'pro_options'  => 4,
			),
		),
		'logs'            => array(
			'title'       => _x( 'Logs', 'post type general name', 'secupress' ),
			'icon'        => 'logs',
			'summaries'   => array(
				'small'  => __( 'Monitor everything', 'secupress' ),
				'normal' => __( 'Keep an eye on what happened on your website at any time. Also, control banned IPs from our modules here.', 'secupress' ),
			),
			'with_form'   => false,
			'description' => array(
				__( 'Keep an eye on what happened on your website at any time. Also, control banned IPs from our modules here.', 'secupress' ),
			),
			'counts' => array(
				'free_options' => 4,
				'pro_options'  => 0,
			),
		),
	);

	if ( class_exists( 'WooCommerce' ) || class_exists( 'SitePress' ) ) {
		++$modules['sensitive-data']['counts']['free_options'];
	}

	if ( function_exists( 'secupress_is_white_label' ) && ! secupress_is_white_label() ) {
		$modules['services'] = array(
			'title'       => __( 'Services', 'secupress' ),
			'icon'        => 'services',
			'summaries'   => array(
				'small'  => __( 'Post Hack & Pro Configuration', 'secupress' ),
				'normal' => sprintf( __( 'Let us configure %s on your site and benefit from our expertise. Get help from our experts. This page contains our services designed to help you with the plugin.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
			'description' => array(
				sprintf( __( 'Let us configure %s on your site and benefit from our expertise. Get help from our experts. This page contains our services designed to help you with the plugin.', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
			),
		);

		if ( $should_be_pro ) {
			$modules['get-pro'] = array(
				'title'       => __( 'Get Pro', 'secupress' ),
				'icon'        => 'secupress',
				'summaries'   => array(
					'small'  => __( 'Do more with the Pro version', 'secupress' ),
					'normal' => __( 'Access more modules and options to automate the security of your website.', 'secupress' ),
				),
				'description' => array(
					__( 'Access more modules and options to automate the security of your website.', 'secupress' ),
				),
			);
		}
	}

	return $modules;
}


/**
 * Activate a sub-module.
 *
 * @since 1.0
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * Add a sub-module (de)activation notice.
 *
 * @since 1.0
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
		secupress_add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
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
		secupress_add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
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
		secupress_add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
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
 * @since 1.3 Moved to global scope.
 * @author Grégory Viguier
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
			secupress_add_settings_error( 'general', 'apache_manual_edit', $message, 'error' );
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
			secupress_add_settings_error( 'general', 'iis7_manual_edit', $message, 'error' );
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
		secupress_add_settings_error( 'general', 'nginx_manual_edit', $message, 'error' );
		return false;
	}

	// Server not supported.
	$message  = sprintf( __( '%s:', 'secupress' ), $title ) . ' ';
	$message .= __( 'It seems your server does not use <strong>Apache</strong>, <strong>Ngnix</strong>, nor <strong>IIS7</strong>. This module won\'t work.', 'secupress' );
	secupress_add_settings_error( 'general', 'unknown_os', $message, 'error' );
	return false;
}


/**
 * Get the counts of Free & Pro modules, or Free or Pro individually.
 *
 * @since 1.0.5
 * @author Geoffrey Crofte
 *
 * @param  (string) $type Null by default, "free" or "pro" string expected.
 *
 * @return (array|int)    Array of both types of module count, or an individual count
 */
function secupress_get_options_counts( $type = null ) {
	$modules = secupress_get_modules();
	$counts = array( 'free' => 0, 'pro' => 0 );

	foreach ( $modules as $mod ) {
		$counts['free'] = ! empty( $mod['counts']['free_options'] ) ? $counts['free'] + $mod['counts']['free_options'] : $counts['free'];
		$counts['pro']  = ! empty( $mod['counts']['pro_options'] ) ? $counts['pro'] + $mod['counts']['pro_options'] : $counts['pro'];
	}

	return ! empty( $counts[ $type ] ) ? $counts[ $type ] : $counts;
}


/**
 * Get a list of all active sub-modules.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @return (array) An array of arrays with the modules as keys and lists of sub-modules as values.
 */
function secupress_get_active_submodules() {
	global $wpdb;

	// Try to get the cache.
	$active_submodules = secupress_get_site_transient( SECUPRESS_ACTIVE_SUBMODULES );

	if ( is_array( $active_submodules ) ) {
		return $active_submodules;
	}

	if ( is_multisite() ) {
		$results = $wpdb->get_results( "SELECT meta_value AS module, REPLACE( meta_key, 'secupress_active_submodule_', '' ) AS submodule FROM $wpdb->sitemeta WHERE meta_key LIKE 'secupress\_active\_submodule\_%' ORDER BY meta_value, meta_key" );
	} else {
		$results = $wpdb->get_results( "SELECT option_value AS module, REPLACE( option_name, 'secupress_active_submodule_', '' ) AS submodule FROM $wpdb->options WHERE option_name LIKE 'secupress\_active\_submodule\_%' ORDER BY option_value, option_name" );
	}

	if ( ! $results ) {
		secupress_set_site_transient( SECUPRESS_ACTIVE_SUBMODULES, array() );
		return array();
	}

	$active_submodules = array();

	foreach ( $results as $result ) {
		if ( ! isset( $active_submodules[ $result->module ] ) ) {
			$active_submodules[ $result->module ] = array();
		}

		$active_submodules[ $result->module ][] = sanitize_key( $result->submodule );
	}

	secupress_set_site_transient( SECUPRESS_ACTIVE_SUBMODULES, $active_submodules );

	return $active_submodules;
}


/**
 * Check whether a sub-module is active.
 *
 * @since 1.0
 *
 * @param (string) $module    A module.
 * @param (string) $submodule A sub-module.
 * @author Grégory Viguier
 *
 * @return (bool)
 */
function secupress_is_submodule_active( $module, $submodule ) {
	$submodule = sanitize_key( $submodule );

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		$is_active = get_site_option( 'secupress_active_submodule_' . $submodule );
		$is_active = $is_active && $module === $is_active;

		if ( $is_active && ! secupress_is_pro() && secupress_submodule_is_pro( $module, $submodule ) ) {
			return false;
		}

		return $is_active;
	}

	$active_submodules = secupress_get_active_submodules();

	if ( empty( $active_submodules[ $module ] ) || ! is_array( $active_submodules[ $module ] ) ) {
		return false;
	}

	$active_submodules[ $module ] = array_flip( $active_submodules[ $module ] );

	$is_active = isset( $active_submodules[ $module ][ $submodule ] );

	if ( $is_active && ! secupress_is_pro() && secupress_submodule_is_pro( $module, $submodule ) ) {
		return false;
	}

	return $is_active;
}


/**
 * Get a list of all active Pro sub-modules.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @return (array) An array of arrays with the modules as keys and lists of sub-modules as values.
 */
function secupress_get_active_pro_submodules() {
	static $active_submodules_cache;
	static $active_pro_submodules;

	$active_submodules_current = secupress_get_active_submodules();

	if ( $active_submodules_cache !== $active_submodules_current ) {
		$active_submodules_cache = $active_submodules_current;
		unset( $active_pro_submodules );
	}

	if ( isset( $active_pro_submodules ) ) {
		return $active_pro_submodules;
	}

	$active_pro_submodules = array();

	if ( $active_submodules_current ) {
		foreach ( $active_submodules_current as $module => $submodules ) {
			foreach ( $submodules as $i => $submodule ) {
				if ( secupress_submodule_is_pro( $module, $submodule ) ) {
					if ( empty( $active_pro_submodules[ $module ] ) ) {
						$active_pro_submodules[ $module ] = array();
					}
					$active_pro_submodules[ $module ][] = $submodule;
				}
			}
		}
	}

	return $active_pro_submodules;
}


/**
 * Tell if a sub-module is Pro.
 *
 * @since 1.1.4
 * @author Grégory Viguier
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 *
 * @return (bool) True if Pro. False otherwize.
 */
function secupress_submodule_is_pro( $module, $submodule ) {
	static $paths = array();

	$key = $module . '|' . $submodule;

	if ( ! isset( $paths[ $key ] ) ) {
		$file_path = sanitize_key( $module ) . '/plugins/' . sanitize_key( $submodule ) . '.php';

		if ( defined( 'SECUPRESS_PRO_MODULES_PATH' ) ) {
			$paths[ $key ] = file_exists( SECUPRESS_PRO_MODULES_PATH . $file_path );
		} else {
			$paths[ $key ] = ! file_exists( SECUPRESS_MODULES_PATH . $file_path );
		}
	}

	return $paths[ $key ];
}


/**
 * Get a sub-module file path.
 *
 * @since 1.0
 * @author Grégory Viguier
 *
 * @param (string) $module    The module.
 * @param (string) $submodule The sub-module.
 *
 * @return (string|bool) The file path on success. False on failure.
 */
function secupress_get_submodule_file_path( $module, $submodule ) {
	$file_path = sanitize_key( $module ) . '/plugins/' . sanitize_key( $submodule ) . '.php';

	if ( defined( 'SECUPRESS_PRO_MODULES_PATH' ) && file_exists( SECUPRESS_PRO_MODULES_PATH . $file_path ) ) {
		return SECUPRESS_PRO_MODULES_PATH . $file_path;
	}

	if ( file_exists( SECUPRESS_MODULES_PATH . $file_path ) ) {
		return SECUPRESS_MODULES_PATH . $file_path;
	}

	return false;
}
