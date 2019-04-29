<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/** --------------------------------------------------------------------------------------------- */
/** MIGRATE / UPGRADE =========================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'secupress.loaded', 'secupress_upgrader', 9 );
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

	if ( defined( 'SECUPRESS_PRO_VERSION' ) && ( ! defined( 'SECUPRESS_PRO_SECUPRESS_MIN' ) || version_compare( SECUPRESS_VERSION, SECUPRESS_PRO_SECUPRESS_MIN ) >= 0 ) ) {
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

		// Free version.
		$options['version'] = SECUPRESS_VERSION;

		// Pro version.
		if ( did_action( 'secupress_pro.first_install' ) || did_action( 'secupress_pro.upgrade' ) ) {
			$options['pro_version'] = SECUPRESS_PRO_VERSION;
		}

		// First install.
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

		/**
		 * From uninstall.php.
		 */

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
			$wpdb->query( sprintf( "DELETE FROM $wpdb->postmeta WHERE post_id IN (%s)", implode( ',', $post_ids ) ) ); // WPCS: unprepared SQL ok.

			// Delete Posts.
			$wpdb->query( sprintf( "DELETE FROM $wpdb->posts WHERE ID IN (%s)", implode( ',', $post_ids ) ) ); // WPCS: unprepared SQL ok.
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
		$wpconfig_filepath = secupress_is_wpconfig_writable();

		if ( $wpconfig_filepath ) {
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

	// < 1.2.6.1
	if ( version_compare( $actual_version, '1.2.6.1', '<' ) ) {
		// New API route and response format.
		delete_transient( 'secupress_pro_plans' );
	}

	// < 1.3
	if ( version_compare( $actual_version, '1.3' ) < 0 ) {
		// Remove 'OrangeBot' from the Bad User Agents list.
		$user_agents_options = get_option( 'secupress_firewall_settings' );

		if ( is_array( $user_agents_options ) && ! empty( $user_agents_options['bbq-headers_user-agents-list'] ) ) {
			$user_agents_options['bbq-headers_user-agents-list'] = secupress_sanitize_list( $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = explode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			$user_agents_options['bbq-headers_user-agents-list'] = array_diff( $user_agents_options['bbq-headers_user-agents-list'], array( 'OrangeBot' ) );
			$user_agents_options['bbq-headers_user-agents-list'] = implode( ', ', $user_agents_options['bbq-headers_user-agents-list'] );
			update_option( 'secupress_firewall_settings', $user_agents_options );
		}

		// New way to store scans and fixes.
		$scanners     = secupress_get_scanners();
		$scanners     = call_user_func_array( 'array_merge', $scanners );
		$scanners     = array_map( 'strtolower', $scanners );
		$sub_scanners = secupress_get_tests_for_ms_scanner_fixes();
		$sub_scanners = array_map( 'strtolower', $sub_scanners );
		$sub_scanners = array_flip( $sub_scanners );
		$is_multisite = is_multisite();

		$scan_results = get_site_option( 'secupress_scanners' );
		$fix_results  = get_site_option( 'secupress_fixes' );
		$sub_results  = get_site_option( 'secupress_fix_sites' );

		if ( ! wp_using_ext_object_cache() ) {
			secupress_load_network_options( $scanners, '_site_transient_secupress_scan_' );
			secupress_load_network_options( $scanners, '_site_transient_secupress_fix_' );
			secupress_load_network_options( $sub_scanners, '_site_transient_secupress_fix_sites_' );
		}

		foreach ( $scanners as $scan_name ) {
			/**
			 * Scan.
			 */
			// Try the transient first (probability we got one is near 0).
			$result = secupress_get_site_transient( 'secupress_scan_' . $scan_name );

			if ( false !== $result ) {
				secupress_delete_site_transient( 'secupress_scan_' . $scan_name );
			}

			$result = $result && is_array( $result ) ? $result : false;

			if ( ! $result && ! empty( $scan_results[ $scan_name ] ) && is_array( $scan_results[ $scan_name ] ) ) {
				$result = $scan_results[ $scan_name ];
			}

			$get_fix = true;

			if ( $result ) {
				SecuPress_Scanner_Results::update_scan_result( $scan_name, $result );

				if ( 'good' === $result['status'] ) {
					// No need for a fix in that case.
					$get_fix = false;
				}
			}

			/**
			 * Fix.
			 */
			// Try the transient first (probability we got one is near 0).
			$result = secupress_get_site_transient( 'secupress_fix_' . $scan_name );

			if ( false !== $result ) {
				secupress_delete_site_transient( 'secupress_fix_' . $scan_name );
			}

			if ( $get_fix ) {
				$result = $result && is_array( $result ) ? $result : false;

				if ( ! $result && ! empty( $fix_results[ $scan_name ] ) && is_array( $fix_results[ $scan_name ] ) ) {
					$result = $fix_results[ $scan_name ];
				}

				if ( $result ) {
					SecuPress_Scanner_Results::update_fix_result( $scan_name, $result );
				}
			}

			/**
			 * Scan and Fix of subsites..
			 */
			// Try the transient first (probability we got one is near 0).
			$result = secupress_get_site_transient( 'secupress_fix_sites_' . $scan_name );

			if ( false !== $result ) {
				secupress_delete_site_transient( 'secupress_fix_sites_' . $scan_name );
			}

			if ( ! $is_multisite || ! isset( $sub_scanners[ $scan_name ] ) ) {
				continue;
			}

			$result = $result && is_array( $result ) ? $result : false;

			if ( ! $result && ! empty( $sub_results[ $scan_name ] ) && is_array( $sub_results[ $scan_name ] ) ) {
				$result = $sub_results[ $scan_name ];
			}

			if ( $result ) {
				SecuPress_Scanner_Results::update_sub_sites_result( $scan_name, $result );
			}
		}

		if ( false !== $scan_results ) {
			delete_site_option( 'secupress_scanners' );
		}

		if ( false !== $fix_results ) {
			delete_site_option( 'secupress_fixes' );
		}

		if ( false !== $sub_results ) {
			delete_site_option( 'secupress_fix_sites' );
		}
	}

	// < 1.3.1
	if ( secupress_is_submodule_active( 'users-login', 'move-login' ) && version_compare( $actual_version, '1.3.1', '<' ) ) {
		// Remove move login rules.
		if ( ! function_exists( 'secupress_move_login_write_rules' ) ) {
			include( SECUPRESS_MODULES_PATH . 'users-login/plugins/inc/php/move-login/admin.php' );
		}
		secupress_move_login_write_rules();
	}

	// < 1.4.3
	if ( version_compare( $actual_version, '1.4.3', '<' ) ) {

		if ( secupress_has_pro() ) {
			secupress_deactivate_submodule( 'users-login', 'nonlogintimeslot' );
			secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'users-login/plugins/nonlogintimeslot.php' );
		}

		secupress_deactivate_submodule( 'file-system', 'directory-index' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'file-system/plugins/directory-index.php' );

		secupress_deactivate_submodule( 'wordpress-core', 'wp-config-constant-unfiltered-html' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'wordpress-core/plugins/wp-config-constant-unfiltered-html.php' );

		secupress_deactivate_submodule( 'sensitive-data', 'restapi' );
		secupress_remove_old_plugin_file( SECUPRESS_MODULES_PATH . 'sensitive-data/plugins/restapi.php' );

		set_site_transient( 'secupress-common', time(), 2 * DAY_IN_SECONDS );
	}

	// < 1.4.4
	if ( version_compare( $actual_version, '1.4.4', '<' ) ) {
		$value = secupress_get_module_option( 'bbq-headers_user-agents-list', secupress_firewall_bbq_headers_user_agents_list_default(), 'firewall' );
		$value = str_replace( 'Wget, ', '', $value );
		secupress_update_module_option( 'bbq-headers_user-agents-list', $value, 'firewall' );
	}

	// < 1.4.5
	if ( secupress_has_pro() && version_compare( $actual_version, '1.4.5', '<' ) ) {
		secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'antispam/callbacks.php' );
	}

	// < 1.4.9
	if ( secupress_has_pro() && version_compare( $actual_version, '1.4.9', '<' ) ) {
		secupress_deactivate_submodule( 'sensitive-data', array( 'page-protect', 'profile-protect', 'options-protect' ) );
		secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'sensitive-data/plugins/options-protect.php' );
		secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'sensitive-data/plugins/profile-protect.php' );
		secupress_remove_old_plugin_file( SECUPRESS_PRO_MODULES_PATH . 'sensitive-data/plugins/page-protect.php' );
	}

}

/**
 * Try to delete an old plugin file removed in a particular version, if not, will empty the file, if not, will rename it, if still not well… ¯\_(ツ)_/¯.
 *
 * @since 1.4.3
 * @param (string) $file The file to be deleted.
 * @author Julio Potier
 **/
function secupress_remove_old_plugin_file( $file ) {
	// Is it a sym link ?
	if ( is_link( $file ) ) {
		$file = @readlink( $file );
	}
	// Try to delete.
	if ( file_exists( $file ) && ! @unlink( $file ) ) {
		// Or try to empty it.
		$fh = @fopen( $file, 'w' );
		$fw = @fwrite( $fh, '<?php // File removed by SecuPress' );
		@fclose( $fh );
		if ( ! $fw ) {
			// Or try to rename it.
			return @rename( $file, $file . '.old' );
		}
	}
	return true;
}


add_action( 'admin_init', 'secupress_better_changelog' );
/**
 * If the plugin is secupress free or pro, let's add our changlog content
 *
 * @since 1.4.3
 * @author Julio Potier
 **/
function secupress_better_changelog() {
	if ( isset( $_GET['tab'], $_GET['plugin'], $_GET['section'] )
	&& ( 'secupress' === $_GET['plugin'] || 'secupress-pro' === $_GET['plugin'] )
	&& 'changelog' === $_GET['section'] && 'plugin-information' === $_GET['tab'] ) {
		remove_action( 'install_plugins_pre_plugin-information', 'install_plugin_information' );
		add_action( 'install_plugins_pre_plugin-information', 'secupress_hack_changelog' );
	}
}

/**
 * Will display our changelog content wiht our CSS
 *
 * @since 1.4.3
 * @author Julio Potier
 **/
function secupress_hack_changelog() {
	global $admin_body_class;

	$api = plugins_api( 'plugin_information', array(
		'slug' => 'secupress',
		'is_ssl' => is_ssl(),
		'fields' => [ 'short_description' => false,
					'reviews' => false,
					'downloaded' => false,
					'downloadlink' => false,
					'last_updated' => false,
					'added' => false,
					'tags' => false,
					'homepage' => false,
					'donate_link' => false,
					'ratings' => false,
					'active_installs' => true,
					'banners' => true,
					'sections' => true,
				]
	) );

	if ( is_wp_error( $api ) ) {
		wp_die( $api );
	}

	$changelog_content = $api->sections['changelog'];
	$changelog_content = explode( "\n", $changelog_content );
	$changelog_content = array_slice( $changelog_content, 0, array_search( '</ul>', $changelog_content, true ) );
	$changelog_content = array_map( 'strip_tags', $changelog_content );
	$changelog_version = array_shift( $changelog_content );
	$changelog_content = array_filter( $changelog_content );
	$changelog_date    = array_shift( $changelog_content );
	$pro_suffix        = secupress_has_pro() ? 'Pro ' : 'Free ';
	$banner            = secupress_has_pro() ? 'banner-secupress-pro.jpg' : 'banner-1544x500.png';

	iframe_header( __( 'Plugin Installation' ) );
	?>
	<style type="text/css">
		body {
			color: #333;
			font-family: Helvetica, Arial, sans-serif;
			margin: 0;
			padding: 0;
			background-color: #fff
		}

		section {
			margin: 20px 25px;
			max-width: 830px
		}

		header {
			position: relative;
			margin-bottom: 20px;
			width: 100%;
			max-width: 830px;
			height: 276px;
			color: #fff;
		}

		#plugin-information-title.with-banner div.vignette {
			background-image: url( 'https://plugins.svn.wordpress.org/secupress/assets/<?php echo $banner; ?>' );
			background-size: contain;
		}

		header h1,
		header h2 {
			font-family: "HelveticaNeue-Light", "Helvetica Neue Light", "Helvetica Neue", sans-serif;
			font-size: 2em;
			font-weight: normal;
			margin: 0;
			color: #fff;
			line-height: 1em
		}

		header h2 {
			font-size: 1.4em;
			margin-bottom: 3px
		}

		hgroup {
			float: right;
			padding-right: 50px
		}

		h2 {
			font-size: 1.2em
		}

		ul {
			margin-bottom: 30px
		}

		li {
			margin-bottom: 0.5em
		}

		.changelog tr {
			line-height: 1.5em;
		}

		.changelog td {
			padding: 3px;
			font-size: 15px;
			vertical-align: middle;
		}

		.changelog .type {
			font-size: 12px;
			text-transform: uppercase;
			padding-right: 15px;
			padding-top: 5px;
			padding-left: 0;
			text-align: left;
			color: #999;
			min-width: 100px;
			border-right: 2px solid #eee;
		}

		.changelog .type, .changelog .description {
			vertical-align: top;
		}

		code {
			background-color: #EEE;
			padding: 2px
		}

		.star-rating {
			display: inline;
		}

		#plugin-information-footer {
			text-align: center;
			line-height: 1.7em;
		}

	</style>
</head>

<body class="$admin_body_class">

<header id="plugin-information-title" class="with-banner">
	<div class="vignette"></div>
	<h2>SecuPress <?php echo $pro_suffix; ?> <?php echo esc_html( $changelog_version ); ?> – <?php echo esc_html( $changelog_date ); ?></h2>
</header>

<section id="plugin-information-scrollable">
	<table class="changelog">
	<?php
	foreach ( $changelog_content as $content ) {
		if ( ! $content ) {
			continue;
		}
		$content = explode( ' ', $content, 2 );
		?>
		<tr>
			<td class="type"><?php echo wp_kses_post( '<strong>' . str_replace( '#', '</strong>&nbsp;#', reset( $content ) ) ); ?></td>
			<td class="description"><?php echo wp_kses_post( end( $content ) ); ?></td>
		</tr>
		<?php
	}
	?>
		<tr>
			<td class="type"><strong><?php _e( 'Full Changelog', 'secupress' ); ?></strong></td>
			<td class="description"><a href="<?php echo SECUPRESS_WEB_MAIN; ?>changelog/" target="_blank"><?php echo SECUPRESS_WEB_MAIN; ?>changelog/</a></td>
		</tr>
	</table>
	<hr>
	<?php
	$status = install_plugin_install_status( $api );
	if ( $status['url'] ) {
		echo '<p><a data-slug="' . esc_attr( $api->slug ) . '" data-plugin="' . esc_attr( $status['file'] ) . '" id="plugin_update_from_iframe" class="button button-primary right" href="' . esc_url( $status['url'] ) . '" target="_parent">' . __( 'Install Update Now' ) . '</a></p>';
	}
	if ( ! secupress_has_pro() ) {
	?>
	<p><a href="<?php echo SECUPRESS_WEB_MAIN; ?>pricing/" class="button button-secondary"><?php _e( 'Get SecuPress Pro Now!', 'secupress' ); ?></a></p>
	<?php
	}
	?>
</section>

<div id="plugin-information-footer">
	<strong><?php _e( 'Requires WordPress Version:' ); ?></strong>
	<?php
	printf( __( '%s or higher' ), $api->requires );

	if ( ! empty( $api->requires_php ) ) {
		echo '& PHP ' . printf( __( '%s or higher' ), $api->requires );
	}
	?> |
	<strong><?php _e( 'Compatible up to:' ); ?></strong>
	<?php echo $api->tested; ?>
	<br>
	<strong><?php _e( 'Active Installations:' ); ?></strong>
	<?php
	if ( $api->active_installs >= 1000000 ) {
		_ex( '1+ Million', 'Active plugin installations' );
	} elseif ( 0 === $api->active_installs ) {
		_ex( 'Less Than 10', 'Active plugin installations' );
	} else {
		echo number_format_i18n( $api->active_installs ) . '+';
	}
	?> |
	<strong><?php _e( 'Average Rating' ); ?>:</strong>
	<?php wp_star_rating( [ 'type' => 'percent', 'rating' => $api->rating, 'number' => $api->num_ratings ] ); ?>
	<p aria-hidden="true" class="fyi-description"><?php printf( _n( '(based on %s rating)', '(based on %s ratings)', $api->num_ratings ), number_format_i18n( $api->num_ratings ) ); ?></p>
	<br>
</div>
<?php
iframe_footer();
exit;
}
