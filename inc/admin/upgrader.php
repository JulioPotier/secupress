<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* MIGRATE / UPGRADE ============================================================================ */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_init', 'secupress_upgrader' );
/**
 * Tell WP what to do when admin is loaded aka upgrader
 *
 * @since 1.0
 */
function secupress_upgrader() {
	$actual_version = secupress_get_option( 'version' );

	// You can hook the upgrader to trigger any action when SecuPress is upgraded.
	// First install.
	if ( ! $actual_version ) {
		/**
		 * Allow to prevent plugin first install hooks to fire.
		 *
		 * @since 1.0
		 *
		 * @param (bool) $prevent True to prevent triggering first install hooks. False otherwise.
		 */
		if ( ! apply_filters( 'secupress.prevent_first_install', false ) ) {
			/**
			 * Fires on the plugin first install.
			 *
			 * @since 1.0
			 *
			 * @param (string) $module The module to reset. "all" means all modules at once.
			 */
			do_action( 'secupress.first_install', 'all' );
		}

		secupress_maybe_handle_license( 'activate' );
	}
	// Already installed but got updated.
	elseif ( SECUPRESS_VERSION !== $actual_version ) {
		$new_version = SECUPRESS_VERSION;
		/**
		 * Fires when SecuPress is upgraded.
		 *
		 * @since 1.0
		 *
		 * @param (string) $new_version    The version being upgraded to.
		 * @param (string) $actual_version The previous version.
		 */
		do_action( 'secupress.upgrade', $new_version, $actual_version );
	}

	if ( defined( 'SECUPRESS_PRO_VERSION' ) ) {
		$actual_pro_version = secupress_get_option( 'pro_version' );

		// You can hook the upgrader to trigger any action when SecuPress Pro is upgraded.
		// First install.
		if ( ! $actual_pro_version ) {
			/**
			 * Allow to prevent SecuPress Pro first install hooks to fire.
			 *
			 * @since 1.1.4
			 *
			 * @param (bool) $prevent True to prevent triggering first install hooks. False otherwise.
			 */
			if ( ! apply_filters( 'secupress_pro.prevent_first_install', false ) ) {
				/**
				 * Fires on SecuPress Pro first install.
				 *
				 * @since 1.1.4
				 *
				 * @param (string) $module The module to reset. "all" means all modules at once.
				 */
				do_action( 'secupress_pro.first_install', 'all' );
			}

			secupress_maybe_handle_license( 'activate', true );
		}
		// Already installed but got updated.
		elseif ( SECUPRESS_PRO_VERSION !== $actual_pro_version ) {
			$new_pro_version = SECUPRESS_PRO_VERSION;
			/**
			 * Fires when SecuPress Pro is upgraded.
			 *
			 * @since 1.0
			 *
			 * @param (string) $new_pro_version    The version being upgraded to.
			 * @param (string) $actual_pro_version The previous version.
			 */
			do_action( 'secupress_pro.upgrade', $new_pro_version, $actual_pro_version );
		}
	}

	// If any upgrade has been done, we flush and update version.
	if ( did_action( 'secupress.first_install' ) || did_action( 'secupress.upgrade' ) || did_action( 'secupress_pro.first_install' ) || did_action( 'secupress_pro.upgrade' ) ) {

		// Do not use secupress_get_option() here.
		$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
		$options = is_array( $options ) ? $options : array();
		$options['version'] = SECUPRESS_VERSION;

		if ( defined( 'SECUPRESS_PRO_VERSION' ) ) {
			$options['pro_version'] = SECUPRESS_PRO_VERSION;
		}

		if ( did_action( 'secupress.first_install' ) ) {
			$options['hash_key']     = secupress_generate_key( 64 );
			$options['install_time'] = time();
		}

		secupress_update_options( $options );
	}
}


add_action( 'secupress.upgrade', 'secupress_new_upgrade', 10, 2 );
/**
 * What to do when SecuPress is updated, depending on versions.
 *
 * @since 1.0
 *
 * @param (string) $secupress_version The version being upgraded to.
 * @param (string) $actual_version    The previous version.
 */
function secupress_new_upgrade( $secupress_version, $actual_version ) {
	global $wpdb;

	// < 1.0
	if ( version_compare( $actual_version, '1.0', '<' ) ) {

		secupress_deactivation();

		// From uninstall.php.

		// Transients.
		$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_transient_secupress_%' OR option_name LIKE '_transient_secupress-%'" );
		array_map( 'delete_transient', $transients );

		// Site transients.
		$transients = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE '_site_transient_secupress_%' OR option_name LIKE '_site_transient_secupress-%'" );
		array_map( 'delete_site_transient', $transients );

		if ( is_multisite() ) {
			$transients = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE '_site_transient_secupress_%' OR meta_key LIKE '_site_transient_secupress-%'" );
			array_map( 'delete_site_transient', $transients );
		}

		// Options.
		$options = $wpdb->get_col( "SELECT option_name FROM $wpdb->options WHERE option_name LIKE 'secupress_%'" );
		array_map( 'delete_option', $options );

		if ( is_multisite() ) {
			// Site options.
			$options = $wpdb->get_col( "SELECT meta_key FROM $wpdb->sitemeta WHERE meta_key LIKE 'secupress_%'" );
			array_map( 'delete_site_option', $options );
		}

		// User metas.
		$wpdb->query( "DELETE FROM $wpdb->usermeta WHERE meta_key LIKE 'secupress_%' OR meta_key LIKE '%_secupress_%'" );

		secupress_activation();
	}

	// < 1.0.3
	if ( version_compare( $actual_version, '1.0.3', '<' ) ) {
		// Remove some User Agents that are too generic from the settings.
		$user_agents_options = get_option( 'secupress_firewall_settings' );

		if ( is_array( $user_agents_options ) && ! empty( $user_agents_options['bbq-headers_user-agents-list'] ) ) {
			$user_agents_options['bbq-headers_user-agents-list'] = secupress_sanitize_list( $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = explode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = array_diff( $user_agents_options['bbq-headers_user-agents-list'], array( 'attache', 'email', 'Fetch', 'Link', 'Ping', 'Proxy' ) );
			$user_agents_options['bbq-headers_user-agents-list'] = implode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			update_option( 'secupress_firewall_settings', $user_agents_options );
		}
	}

	// < 1.0.4
	if ( version_compare( $actual_version, '1.0.4', '<' ) ) {
		// Get post ids from logs.
		$post_ids = $wpdb->get_col( "SELECT ID FROM $wpdb->posts WHERE post_type LIKE 'secupress_log_%'" );

		if ( $post_ids ) {
			// Delete Postmeta.
			$sql = sprintf( "DELETE FROM $wpdb->postmeta WHERE post_id IN (%s)", implode( ",", $post_ids ) );
			$wpdb->query( $sql );

			// Delete Posts.
			$sql = sprintf( "DELETE FROM $wpdb->posts WHERE ID IN (%s)", implode( ",", $post_ids ) );
			$wpdb->query( $sql );
		}
	}

	// < 1.0.6
	if ( version_compare( $actual_version, '1.0.6', '<' ) ) {
		// Make sure affected roles are not empty (sanitization will do the job).
		$users_login_settings = get_site_option( 'secupress_users-login_settings' );
		update_site_option( 'secupress_users-login_settings', $users_login_settings );
	}

	// < 1.1.4
	if ( version_compare( $actual_version, '1.1.4', '<' ) ) {
		// Lots of things have changed on the sub-modules side.
		secupress_maybe_handle_license( 'activate' );

		$options = get_site_option( SECUPRESS_SETTINGS_SLUG );
		$options = is_array( $options ) ? $options : array();
		$options['install_time'] = time();
		secupress_update_options( $options );

		// PHP version.
		if ( secupress_is_submodule_active( 'discloses', 'php-version' ) && ! secupress_is_submodule_active( 'discloses', 'no-x-powered-by' ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );
		}

		// WP disclose.
		$deactivate = array();

		foreach ( array( 'generator', 'wp-version-css', 'wp-version-js' ) as $submodule ) {
			if ( secupress_is_submodule_active( 'discloses', $submodule ) ) {
				$deactivate[] = $submodule;
			}
		}

		if ( $deactivate ) {
			secupress_deactivate_submodule( 'discloses', $deactivate );
			secupress_activate_submodule( 'discloses', 'wp-version' );
		}

		// WooCommerce and WPML.
		foreach ( array( 'woocommerce', 'wpml' ) as $wp_plugin ) {
			$deactivate = array();

			foreach ( array( 'generator', 'version-css', 'version-js' ) as $path_part ) {
				if ( secupress_is_submodule_active( 'discloses', $wp_plugin . '-' . $path_part ) ) {
					$deactivate[] = $wp_plugin . '-' . $path_part;
				}
			}

			if ( $deactivate ) {
				secupress_deactivate_submodule( 'discloses', $deactivate );
				secupress_activate_submodule( 'discloses', $wp_plugin . '-version' );
			}
		}

		// `wp-config.php` constants.
		$wpconfig_filepath = secupress_find_wpconfig_path();
		$is_writable       = $wpconfig_filepath && wp_is_writable( $wpconfig_filepath );

		if ( $is_writable ) {
			$wp_filesystem = secupress_get_filesystem();
			$file_content  = $wp_filesystem->get_contents( $wpconfig_filepath );
			$pattern       = '@# BEGIN SecuPress Correct Constants Values(.*)# END SecuPress\s*?@Us';

			if ( preg_match( $pattern, $file_content, $matches ) ) {
				$new_content = $matches[1];
				$replaced    = array();
				$constants   = array(
					'DISALLOW_FILE_EDIT'       => 'file-edit',
					'DISALLOW_UNFILTERED_HTML' => 'unfiltered-html',
					'ALLOW_UNFILTERED_UPLOADS' => 'unfiltered-uploads',
				);

				foreach ( $constants as $constant => $submodule_part ) {
					$pattern     = "@^\s*define\s*\(\s*[\"']{$constant}[\"'].*@m";
					$tmp_content = preg_replace( $pattern, '', $new_content );

					if ( null !== $tmp_content && $tmp_content !== $new_content ) {
						// The constant was in the block and has been removed.
						$replaced[]  = 'wp-config-constant-' . $submodule_part;
						$new_content = $tmp_content;
					}
				}

				if ( $replaced ) {
					if ( trim( $new_content ) === '' ) {
						// No constants left, remove the marker too.
						$new_content = '';
					} else {
						$new_content = str_replace( $matches[1], $new_content, $matches[0] );
					}

					// Remove the old constants.
					$new_content = str_replace( $matches[0], $new_content, $file_content );
					$wp_filesystem->put_contents( $wpconfig_filepath, $new_content, FS_CHMOD_FILE );

					// Activate the new sub-modules.
					foreach ( $replaced as $submodule ) {
						secupress_activate_submodule( 'wordpress-core', $submodule );
					}
				}
			}
		}
	}
}
