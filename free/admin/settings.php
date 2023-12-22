<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** CSS, JS, FOOTER ============================================================================= */
/** --------------------------------------------------------------------------------------------- */

add_action( 'doing_dark_mode', 'secupress_add_settings_scripts_for_dark_mode', 11 );
/**
 * Add some CSS for Dark Mode
 *
 * @since 1.4.7
 *
 */
function secupress_add_settings_scripts_for_dark_mode() {
	$suffix    = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version   = $suffix ? SECUPRESS_VERSION : time();
	// SecuPress Dark Mode
	wp_enqueue_style( 'secupress-dark-mode', SECUPRESS_ADMIN_CSS_URL . 'secupress-dark-mode' . $suffix . '.css', array( 'secupress-wordpress-css' ), $version );
}

/*
add_action( 'admin_footer-plugins.php', 'secupress_add_deactivation_form' );
add_action( 'admin_footer-plugins-network.php', 'secupress_add_deactivation_form' );
// Removed in 2.1, for now.
*/
/**
 * Onclude the modal form for deactivation feedback, only if transient is not set
 *
 * @since 2.0
 * @author Julio Potier
 **/
function secupress_add_deactivation_form() {
	$tr = get_site_transient( 'secupress-deactivation-form' );
	if ( ! $tr && ! secupress_is_white_label() && ( ! function_exists( 'wp_get_environment_type' ) || 'production' === wp_get_environment_type() ) ) {
		include( SECUPRESS_ADMIN_PATH . 'modal.php' );
	}
}

add_action( 'admin_enqueue_scripts', 'secupress_add_settings_scripts', 10 );
/**
 * Add some CSS and JS to our settings pages.
 *
 * @since 1.0
 *
 * @param (string) $hook_suffix The current admin page.
 */
function secupress_add_settings_scripts( $hook_suffix ) {

	$suffix    = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version   = $suffix ? SECUPRESS_VERSION : time();
	$css_depts = array();
	$js_depts  = array( 'jquery' );

	// Deactivation Modal removed in 2.1 for now
	// if ( ! function_exists( 'wp_get_environment_type' ) || 'production' === wp_get_environment_type() ) {
	// 	if ( 'plugins.php' === $hook_suffix || 'plugins-network.php' === $hook_suffix ) {
	// 		wp_enqueue_style( 'secupress-modal', SECUPRESS_ADMIN_CSS_URL . 'secupress-modal' . $suffix . '.css', null, SECUPRESS_VERSION );
	// 		wp_enqueue_script( 'secupress-modal', SECUPRESS_ADMIN_JS_URL . 'secupress-modal' . $suffix . '.js', null, SECUPRESS_VERSION, true );
	// 	}
	// }

	// Sweet Alert.
	if ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_modules' === $hook_suffix || 'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners' === $hook_suffix ) {
		// CSS.
		$css_depts = array( 'wpmedia-css-sweetalert2' );
		wp_enqueue_style( 'wpmedia-css-sweetalert2', SECUPRESS_ADMIN_CSS_URL . 'sweetalert2' . $suffix . '.css', array(), '1.3.4' );
		// JS.
		$js_depts  = array( 'jquery', 'wpmedia-js-sweetalert2' );
		wp_enqueue_script( 'wpmedia-js-sweetalert2', SECUPRESS_ADMIN_JS_URL . 'sweetalert2' . $suffix . '.js', array(), '1.3.4', true );
	}

	// WordPress Common CSS.
	wp_enqueue_style( 'secupress-wordpress-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-wordpress' . $suffix . '.css', $css_depts, $version );

	// WordPress Common JS.
	wp_enqueue_script( 'secupress-wordpress-js', SECUPRESS_ADMIN_JS_URL . 'secupress-wordpress' . $suffix . '.js', $js_depts, $version, true );

	$localize_wp = array(
		'isPro'               => (int) secupress_is_pro(),
		'confirmText'         => __( 'OK', 'secupress' ),
		'cancelText'          => __( 'Cancel' ),
	);

	wp_localize_script( 'secupress-wordpress-js', 'SecuPressi18n', $localize_wp );

	$pages = array(
		'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners'  => 1,
		SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_modules'  => 1,
		SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_logs'     => 1,
	);

	SecuPress_Admin_Pointers::enqueue_scripts( $hook_suffix );

	if ( ! isset( $pages[ $hook_suffix ] ) ) {
		return;
	}

   	// SecuPress Common CSS.
	wp_enqueue_style( 'secupress-common-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-common' . $suffix . '.css', array( 'secupress-wordpress-css' ), $version );

	// WordPress Common JS.
	wp_enqueue_script( 'secupress-common-js', SECUPRESS_ADMIN_JS_URL . 'secupress-common' . $suffix . '.js', array( 'secupress-wordpress-js' ), $version, true );

	wp_localize_script( 'secupress-common-js', 'SecuPressi18nCommon', array(
		'confirmText'         => __( 'OK', 'secupress' ),
		'cancelText'          => __( 'Cancel' ),
		'closeText'           => __( 'Close' ),
	) );

	// Settings page.
	if ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-settings-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-settings' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}
	// Modules page.
	elseif ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_modules' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-modules-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-modules' . $suffix . '.css', array( 'secupress-common-css' ), $version );

		// JS.
		wp_enqueue_script( 'secupress-modules-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-modules' . $suffix . '.js', array( 'secupress-common-js' ), $version, true );

		$already_scanned         = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) ) ? 1 : 0;
		$file_monitoring_running = 'off';
		$move_login_nonce        = null;

		if ( ! empty( $_GET['module'] ) ) {
			if ( 'file-system' === $_GET['module'] && function_exists( 'secupress_file_monitoring_get_instance' ) ) {
				$file_monitoring_running = secupress_file_monitoring_get_instance()->is_monitoring_running() ? 'on' : 'off';
				if ( 'on' === $file_monitoring_running ) {
					echo '<meta http-equiv="refresh" content="30;url=' . secupress_admin_url( 'modules', 'file-system' ) . '" />';
				}
			}
			elseif ( 'users-login' === $_GET['module'] ) {
				$move_login_nonce = wp_create_nonce( 'sanitize_move_login_slug' );
			}
		}

		wp_localize_script( 'secupress-modules-js', 'SecuPressi18nModules', array(
			// Roles.
			'selectOneRoleMinimum' => __( 'Select 1 role minimum', 'secupress' ),
			// Generic.
			'confirmTitle'         => __( 'Are you sure?', 'secupress' ),
			'confirmText'          => __( 'OK', 'secupress' ),
			'cancelText'           => __( 'Cancel' ),
			'error'                => __( 'Error', 'secupress' ),
			'unknownError'         => __( 'Unknown error.', 'secupress' ),
			'delete'               => __( 'Delete', 'secupress' ),
			'done'                 => __( 'Done!', 'secupress' ),
			// Backups.
			'confirmDeleteBackups' => __( 'You are about to delete all your backups.', 'secupress' ),
			'yesDeleteAll'         => __( 'Yes, delete all backups', 'secupress' ),
			'deleteAllImpossible'  => __( 'Impossible to delete all backups.', 'secupress' ),
			'deletingAllText'      => __( 'Deleting all backups&hellip;', 'secupress' ),
			'deletedAllText'       => __( 'All backups deleted', 'secupress' ),
			// Backup.
			'confirmDeleteBackup'  => __( 'You are about to delete a backup.', 'secupress' ),
			'yesDeleteOne'         => __( 'Yes, delete this backup', 'secupress' ),
			'deleteOneImpossible'  => __( 'Impossible to delete this backup.', 'secupress' ),
			'deletingOneText'      => __( 'Deleting Backup&hellip;', 'secupress' ),
			'deletedOneText'       => __( 'Backup deleted', 'secupress' ),
			// Backup actions.
			'backupImpossible'     => __( 'Impossible to backup.', 'secupress' ),
			'backupingText'        => __( 'Backuping&hellip;', 'secupress' ),
			'backupedText'         => __( 'Backup done', 'secupress' ),
			// Ban/Whitelist IPs.
			'noBannedIPs'          => __( 'Empty disallowed IP list.', 'secupress' ),
			'noWhitelistIPs'       => __( 'Empty allowed IP list.', 'secupress' ),
			'IPnotFound'           => __( 'IP not found.', 'secupress' ),
			'IPremoved'            => __( 'IP removed.', 'secupress' ),
			'searchResults'        => _x( 'See search result below.', 'adjective', 'secupress' ),
			'searchReset'          => _x( 'Search reset.', 'adjective', 'secupress' ),
			// First scan.
			'alreadyScanned'       => $already_scanned,
			'firstScanTitle'       => __( 'Before setting modules,<br>launch your first scan.', 'secupress' ),
			'firstScanText'        => __( 'It’s an automatic process that will help you secure your website.', 'secupress' ),
			'firstScanButton'      => __( 'Scan my website', 'secupress' ),
			'firstScanURL'         => esc_url( wp_nonce_url( secupress_admin_url( 'scanners' ), 'first_oneclick-scan' ) ) . '&oneclick-scan=1',
			'firstScanImage'       => SECUPRESS_ADMIN_IMAGES_URL . 'icon-radar.png',
			// Expand Textareas.
			'expandTextOpen'       => __( 'Show More', 'secupress' ),
			'expandTextClose'      => __( 'Close' ),
			// Malware Scan.
			'malwareScanStatus'    => $file_monitoring_running,
			'malwareScanError'     => '<span class="dashicons dashicons-dismiss"></span> ' . __( 'AJAX Security Error: Please reload the page manually.', 'secupress' ),
			'MalwareScanURI'       => secupress_admin_url( 'modules', 'file-system' ),
			// Move Login.
			'moveLoginNonce'       => $move_login_nonce,
			// Misc.
			'resetDefault'         => __( 'This will reset the setting values to default for this module.', 'secupress' ),
			'regenKeys'            => __( 'This will change the 8 security keys for your installation.<br>You may need to sign back in.', 'secupress' ),
		) );

	}
	// Scanners page.
	elseif ( 'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-scanner-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-scanner' . $suffix . '.css', array( 'secupress-common-css' ), $version );

		// JS.
		$depts   = array( 'secupress-common-js' );
		$is_main = is_network_admin() || ! is_multisite();

		if ( $is_main ) {
			$depts[] = 'secupress-chartjs';
			$counts  = secupress_get_scanner_counts();

			wp_enqueue_script( 'secupress-chartjs', SECUPRESS_ADMIN_JS_URL . 'chart' . $suffix . '.js', array(), '1.0.2.1', true );

			wp_localize_script( 'secupress-chartjs', 'SecuPressi18nChart', array(
				'good'          => array( 'value' => $counts['good'],          'text' => __( 'Good', 'secupress' ) ),
				'warning'       => array( 'value' => $counts['warning'],       'text' => __( 'Warning', 'secupress' ) ),
				'bad'           => array( 'value' => $counts['bad'],           'text' => __( 'Bad', 'secupress' ) ),
				'notscannedyet' => array( 'value' => $counts['notscannedyet'], 'text' => __( 'Not Scanned Yet', 'secupress' ) ),
			) );
		}

		wp_enqueue_script( 'secupress-scanner-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-scanner' . $suffix . '.js', $depts, $version, true );

		$localize = array(
			'pluginSlug'         => SECUPRESS_PLUGIN_SLUG,
			'step'               => $is_main ? secupress_get_scanner_pagination() : 0,
			'confirmText'        => __( 'OK', 'secupress' ),
			'cancelText'         => __( 'Cancel' ),
			'error'              => __( 'Error', 'secupress' ),
			'fixed'              => __( 'Fixed', 'secupress' ),
			'fixedPartial'       => __( 'Partially fixed', 'secupress' ),
			'notFixed'           => __( 'Not fixed', 'secupress' ),
			'fixit'              => __( 'Fix it', 'secupress' ),
			'oneManualFix'       => __( 'One fix requires your intervention.', 'secupress' ),
			'fixInProgress'      => __( 'Fix in progress&hellip;', 'secupress' ),
			'someManualFixes'    => __( 'Some fixes require your intervention.', 'secupress' ),
			'spinnerUrl'         => admin_url( 'images/wpspin_light-2x.gif' ),
			'reScan'             => _x( 'Scan', 'verb', 'secupress' ),
			'scanDetails'        => __( 'Scan Details', 'secupress' ),
			'fixDetails'         => __( 'Fix Details', 'secupress' ),
			'firstScanURL'       => esc_url( wp_nonce_url( secupress_admin_url( 'scanners' ), 'first_oneclick-scan' ) ) . '&oneclick-scan=1',
			'a11y' => array(
				'scanEnded'    => __( 'Security scan just finished.', 'secupress' ),
				'bulkFixStart' => __( 'Currently fixing…', 'secupress' ) . ' ' . __( 'Please wait until fixing is complete.', 'secupress' ),
			),
			'comingSoon'       => __( 'Coming Soon', 'secupress' ),
			'docNotReady'      => __( 'The documentation is actually under construction, thank you for your patience.', 'secupress' ),
			'offset'           => (int) apply_filters( 'secupress.scanner.scan-speed', (int) secupress_get_option( 'scan-speed', 0 ) ),
		);

		if ( $is_main ) {
			$localize['i18nNonce'] = wp_create_nonce( 'secupress-get-scan-counters' );
		}

		if ( ! empty( $_GET['oneclick-scan'] ) && ! empty( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'first_oneclick-scan' ) && current_user_can( secupress_get_capability() ) ) {
			$localize['firstOneClickScan'] = 1;

			$_SERVER['REQUEST_URI'] = remove_query_arg( array( '_wpnonce', 'oneclick-scan' ) );
		}

		wp_localize_script( 'secupress-scanner-js', 'SecuPressi18nScanner', $localize );
	}
	// Logs page.
	elseif ( SECUPRESS_PLUGIN_SLUG . '_page_' . SECUPRESS_PLUGIN_SLUG . '_logs' === $hook_suffix ) {
		// CSS.
		////// CSS.
		wp_enqueue_style( 'secupress-logs-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-logs' . $suffix . '.css', array( 'secupress-common-css' ), $version );
		wp_enqueue_style( 'secupress-modules-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-modules' . $suffix . '.css', array( 'secupress-common-css' ), $version );
		wp_enqueue_script( 'secupress-logs-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-logs' . $suffix . '.js', array( 'jquery-ui-slider' ), $version );
		$localize = [ 'steps' => secupress_get_http_logs_limits() ];
		wp_localize_script( 'secupress-logs-js', 'SecuPressi18nLogs', $localize );
		add_thickbox();
	}

}


/** --------------------------------------------------------------------------------------------- */
/** PLUGINS LIST ================================================================================ */
/** --------------------------------------------------------------------------------------------- */

add_filter( 'plugin_action_links_' . plugin_basename( SECUPRESS_FILE ), 'secupress_settings_action_links' );
/**
 * Add links to the plugin row.
 *
 * @since 2.0 Add my license link
 * @since 1.0
 *
 * @param (array) $actions An array of links.
 *
 * @return (array) The array of links + our links.
 */
function secupress_settings_action_links( $actions ) {
	if ( ! secupress_is_white_label() ) {
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', esc_url( SECUPRESS_WEB_MAIN . __( 'support', 'secupress' ) ), __( 'Support', 'secupress' ) ) );

		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', esc_url( __( 'https://docs.secupress.me/', 'secupress' ) ), __( 'Docs', 'secupress' ) ) );
	}
	if ( secupress_has_pro() && ! secupress_is_pro() ) { // Pro installed but not yet licence activated.
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', esc_url( secupress_admin_url( 'modules#module-secupress_display_apikey_options' ) ), '<b style="font-variant:small-caps">' . __( 'Add my license', 'secupress' ) . '</b>' ) );
	} else {
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', esc_url( secupress_admin_url( 'modules' ) ), __( 'Settings' ) ) ); // Let WP i18n here.
	}

	return $actions;
}


/** --------------------------------------------------------------------------------------------- */
/** ADMIN MENU ================================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( ( is_multisite() ? 'network_' : '' ) . 'admin_menu', 'secupress_create_menus' );
/**
 * Create the plugin menu and submenus.
 *
 * @since 1.0
 */
function secupress_create_menus() {
	global $menu, $submenu;

	// Add a counter of scans with bad result.
	$cap   = secupress_get_capability();
	if ( ! current_user_can( $cap ) ) {
		return;
	}
	$count = sprintf( ' <span class="update-plugins count-%1$d"><span class="update-count">%1$d</span></span>', secupress_get_scanner_counts( 'bad' ) );

	// Main menu item.
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, $cap, SECUPRESS_PLUGIN_SLUG . '_scanners', 'secupress_scanners', 'dashicons-shield-alt' );

	// Sub-menus.
	add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ) . $count, $cap, SECUPRESS_PLUGIN_SLUG . '_scanners', 'secupress_scanners' );
	add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', __( 'Modules', 'secupress' ),  __( 'Modules', 'secupress' ),           $cap, SECUPRESS_PLUGIN_SLUG . '_modules',  'secupress_modules' );

	if ( ! secupress_is_white_label() ) {
		$title = __( 'More Security', 'secupress' );
		if ( secupress_has_pro() ) {
			$title = __( 'Add my license', 'secupress' );
		}
		if ( ! secupress_is_pro() ) {
			add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', $title, $title, $cap, '__return_false', '__return_false' );
		}
	}

	// Fix `add_menu_page()` nonsense.
	end( $menu );
	$key = key( $menu );
	$menu[ $key ][0] = SECUPRESS_PLUGIN_NAME . $count;

	// Fix `add_submenu_page()` URL.
	if ( ! secupress_is_pro() ) {
		end( $submenu );
		$key = key( $submenu );
		$url = secupress_has_pro() ? esc_url( secupress_admin_url( 'modules' ) . '#module-secupress_display_apikey_options' ) : esc_url( secupress_admin_url( 'get-pro' ) );
		$submenu[ $key ][ count( $submenu[ $key ] ) -1 ] = array( $title, $cap, $url, $title );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** SETTINGS PAGES ============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Settings page.
 *
 * @since 1.0
 */
function secupress_global_settings() {
	if ( ! class_exists( 'SecuPress_Settings' ) ) {
		secupress_require_class( 'settings' );
	}

	$class_name = 'SecuPress_Settings_Global';

	if ( ! class_exists( $class_name ) ) {
		secupress_require_class( 'settings', 'global' );
	}

	if ( secupress_is_pro() ) {
		$class_name = 'SecuPress_Pro_Settings_Global';

		if ( ! class_exists( $class_name ) ) {
			secupress_pro_require_class( 'settings', 'global' );
		}
	}

	$class_name::get_instance()->print_page();
}


/**
 * Modules page.
 *
 * @since 1.0
 */
function secupress_modules() {
	if ( ! class_exists( 'SecuPress_Settings' ) ) {
		secupress_require_class( 'settings' );
	}
	if ( ! class_exists( 'SecuPress_Settings_Modules' ) ) {
		secupress_require_class( 'settings', 'modules' );
	}

	SecuPress_Settings_Modules::get_instance()->print_page();
}

/**
 * Scanners page.
 *
 * @since 1.0
 */
function secupress_scanners() {
	$counts      = secupress_get_scanner_counts();
	$items       = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );
	$reports     = array();
	$last_report = '—';
	$time_offset = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
	$use_grade = secupress_get_module_option( 'advanced-settings_grade-system', true );

	if ( $items ) {
		$last_percent = -1;

		foreach ( $items as $item ) {
			$reports[]    = secupress_formate_latest_scans_list_item( $item, $last_percent );
			$last_percent = $item['percent'];
		}

		$last_report = end( $items );
		$last_report = date_i18n( _x( 'M dS, Y \a\t h:ia', 'Latest scans', 'secupress' ), $last_report['time'] + $time_offset );
	}

	if ( isset( $_GET['step'] ) && 1 === (int) $_GET['step'] ) {
		secupress_set_old_report();
	}

	$currently_scanning_text = '
		<span aria-hidden="true" class="secupress-second-title">' . __( 'Currently scanning', 'secupress' ) . '</span>
		<span class="secupress-scanned-items">
			' . sprintf(
				__( '%1$s&nbsp;/&nbsp;%2$s points' , 'secupress' ),
				'<span class="secupress-scanned-current">0</span>',
				'<span class="secupress-scanned-total">1</span>'
			) . '
		</span>';
	?>
	<div class="wrap">

		<?php secupress_admin_heading( __( 'Scanners', 'secupress' ) ); ?>

		<div class="secupress-wrapper">
			<div class="secupress-section-dark secupress-scanners-header<?php echo $reports ? '' : ' secupress-not-scanned-yet'; ?>">

				<div class="secupress-heading secupress-flex secupress-wrap">
					<div class="secupress-logo-block secupress-flex">
						<div class="secupress-lb-logo">
							<?php echo secupress_get_logo( array( 'width' => 59 ) ); ?>
						</div>
						<div class="secupress-lb-name">
							<p class="secupress-lb-title">
							<?php echo secupress_get_logo_word( array( 'width' => 98, 'height' => 23 ) ); ?>
							</p>
						</div>
					</div>
					<?php if ( ! $reports ) { ?>
					<div class="secupress-col-text">
						<p class="secupress-text-medium"><?php _e( 'First scan', 'secupress' ); ?></p>
						<p><?php _e( 'Here’s how it’s going to work', 'secupress' ); ?></p>
					</div>
					<?php } ?>
					<p class="secupress-label-with-icon secupress-last-scan-result<?php if ( ! $use_grade ) { echo ' hidden'; } ?>">
						<i class="secupress-icon-secupress" aria-hidden="true"></i>
						<span class="secupress-upper"><?php _e( 'Scan results', 'secupress' ); ?></span>
						<span class="secupress-primary"><?php echo $last_report; ?></span>
					</p>
					<p class="secupress-text-end hide-if-no-js">
						<a href="#secupress-more-info" class="secupress-link-icon secupress-open-moreinfo<?php echo $reports ? '' : ' secupress-activated dont-trigger-hide'; ?>" data-trigger="slidedown" data-target="secupress-more-info">
							<span class="icon" aria-hidden="true">
								<i class="secupress-icon-info"></i>
							</span>
							<span class="text">
								<?php _e( 'How does it work?', 'secupress' ); ?>
							</span>
						</a>
					</p>
				</div><!-- .secupress-heading -->

				<?php
				if ( ( secupress_get_scanner_pagination() === 1 || secupress_get_scanner_pagination() === 4 ) ) { ?>
					<div class="secupress-scan-header-main secupress-flex">
						<?php if ( $use_grade ) { ?>
						<div id="sp-tab-scans" class="secupress-tabs-contents secupress-flex">
							<div id="secupress-scan" class="secupress-tab-content" role="tabpanel" aria-labelledby="secupress-l-scan">
								<div class="secupress-flex secupress-chart">

									<div class="secupress-chart-container">
										<canvas class="secupress-chartjs" id="status_chart" width="180" height="180"></canvas>
										<div class="secupress-score"><?php echo $counts['letter']; ?></div>
									</div>

									<div class="secupress-chart-legends-n-note">

										<div class="secupress-scan-infos">
											<p class="secupress-score-text secupress-text-big secupress-m0">
												<?php echo $counts['text']; ?>
											</p>
											<p class="secupress-score secupress-score-subtext secupress-m0"><?php echo $counts['subtext']; ?></p>
										</div>

										<ul class="secupress-chart-legend hide-if-no-js">
											<li class="status-good" data-status="good">
												<span class="secupress-carret"></span>
												<?php _e( 'Good', 'secupress' ); ?>
												<span class="secupress-count-good"></span>
											</li>
											<?php if ( $counts['warning'] > 0 ) : ?>
											<li class="status-warning" data-status="warning">
												<span class="secupress-carret"></span>
												<?php _e( 'Pending', 'secupress' ); ?>
												<span class="secupress-count-warning"></span>
											</li>
											<?php endif; ?>
											<li class="status-bad" data-status="bad">
												<span class="secupress-carret"></span>
												<?php _e( 'Bad', 'secupress' ); ?>
												<span class="secupress-count-bad"></span>
											</li>
											<?php if ( $counts['notscannedyet'] > 0 ) : ?>
											<li class="status-notscannedyet" data-status="notscannedyet">
												<span class="secupress-carret"></span>
												<?php _e( 'New Scan', 'secupress' ); ?>
												<span class="secupress-count-notscannedyet"></span>
											</li>
											<?php endif; ?>
										</ul><!-- .secupress-chart-legend -->

										<?php if ( ! secupress_is_white_label() ) { ?>
											<div id="tweeterA" class="hidden">
												<p>
													<q>
													<?php
													/** Translators: %s is the plugin name */
													$quote = sprintf( __( 'Wow! My website just got an %s grade for security using @SecuPress, what about yours?', 'secupress' ), secupress_get_scanner_counts( 'grade' ) );
													// echo and not _e() because we need the quote later again.
													echo $quote;
													?>
													</q>
												</p>

												<a class="secupress-button secupress-button-mini" target="_blank" title="<?php esc_attr_e( 'Open in a new window.', 'secupress' ); ?>" href="https://twitter.com/intent/tweet?url=<?php
													echo rawurlencode( 'https://secupress.me' ); ?>&amp;text=<?php echo rawurlencode( html_entity_decode( $quote ) ); ?>">
													<span class="icon" aria-hidden="true"><span class="dashicons dashicons-twitter"></span></span>
													<span class="text"><?php esc_html_e( 'Tweet this', 'secupress' ); ?></span>
												</a>

											</div><!-- #tweeterA -->
										<?php } ?>
									</div><!-- .secupress-chart-legends-n-note -->

								</div><!-- .secupress-chart.secupress-flex -->
							</div><!-- .secupress-tab-content -->

							<div id="secupress-latest" class="secupress-tab-content hide-if-js" role="tabpanel" aria-labelledby="secupress-l-latest">

								<h3 class="secupress-text-medium hide-if-js"><?php _e( 'Your last scans', 'secupress' ); ?></h3>

								<div class="secupress-latest-list">
									<ul class="secupress-reports-list">
										<?php
										if ( (bool) $reports ) {
											echo implode( "\n", $reports );
										} else {
											echo '<li class="secupress-empty"><em>' . __( 'You have no other reports for now.', 'secupress' ) . "</em></li>\n";
										}
										?>
									</ul>
								</div><!-- .secupress-latest-list -->

							</div><!-- .secupress-tab-content -->


							<div id="secupress-schedule" class="secupress-tab-content hide-if-js" role="tabpanel" aria-labelledby="secupress-l-schedule">
								<p class="secupress-text-medium">
									<?php _e( 'Schedule your security analysis', 'secupress' ); ?>
								</p>
								<p><?php _e( 'Stay updated on the security of your website. With our automatic scans, there is no need to log in to your WordPress admin to run a scan.', 'secupress' ); ?></p>

								<?php if ( secupress_is_pro() ) :
									$last_schedule = secupress_get_last_scheduled_scan();
									$last_schedule = $last_schedule ? date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress' ), $last_schedule ) : '&mdash;';
									$next_schedule = secupress_get_next_scheduled_scan();
									$next_schedule = $next_schedule ? date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress' ), $next_schedule ) : '&mdash;';
									?>
									<div class="secupress-schedules-infos is-pro">
										<p class="secupress-schedule-last-one">
											<i class="secupress-icon-clock-o" aria-hidden="true"></i>
											<span><?php printf( __( 'Last automatic scan: %s', 'secupress' ), $last_schedule ); ?></span>
										</p>
										<p class="secupress-schedule-next-one">
											<i class="secupress-icon-clock-o" aria-hidden="true"></i>
											<span><?php printf( __( 'Next automatic scan: %s', 'secupress' ), $next_schedule ); ?></span>
										</p>

										<p class="secupress-cta">
											<a href="<?php echo esc_url( secupress_admin_url( 'modules', 'schedules' ) ); ?>#module-scanners" class="secupress-button secupress-button-primary" target="_blank"><?php _e( 'Schedule your next analysis', 'secupress' ); ?></a>
										</p>
									</div><!-- .secupress-schedules-infos -->
								<?php else : ?>
									<div class="secupress-schedules-infos">
										<p class="secupress-schedule-last-one">
											<i class="secupress-icon-clock-o" aria-hidden="true"></i>
											<span><?php printf( __( 'Last automatic scan: %s', 'secupress' ), '&mdash;' ); ?></span>
										</p>
										<p class="secupress-schedule-next-one">
											<i class="secupress-icon-clock-o" aria-hidden="true"></i>
											<span><?php printf( __( 'Next automatic scan: %s', 'secupress' ), '&mdash;' ); ?></span>
										</p>

										<p class="secupress-cta">
											<a href="<?php echo esc_url( secupress_admin_url( 'modules', 'schedules' ) ); ?>#module-scanners" class="secupress-button secupress-button-tertiary" target="_blank"><?php _e( 'Schedule your next analysis', 'secupress' ); ?></a>
										</p>
										<p class="secupress-cta-detail"><?php _e( 'Available in the PRO version', 'secupress' ); ?></p>
									</div><!-- .secupress-schedules-infos -->
								<?php endif; ?>

							</div><!-- .secupress-tab-content -->
						</div><!-- .secupress-tabs-contents -->
						<?php } ?>
						<div class="secupress-tabs-controls <?php if ( ! $use_grade ) { echo 'secupress-inline-block '; } ?>hide-if-no-js">
							<ul class="secupress-tabs secupress-tabs-controls-list" role="tablist" data-content="#sp-tab-scans">
								<li role="presentation"<?php if ( ! $use_grade ) { echo 'class="hidden"'; } ?>>
									<a id="secupress-l-latest" href="#secupress-latest" role="tab" aria-selected="false" aria-controls="secupress-latest">
										<span class="secupress-label-with-icon">
											<i class="secupress-icon-back rounded" aria-hidden="true"></i>
											<span class="secupress-upper"><?php _e( 'Latest scans', 'secupress' ); ?></span>
											<span class="secupress-description"><?php _e( 'View your previous scans', 'secupress' ); ?></span>
										</span>
									</a>
								</li>
								<?php $schedule_scan_url = $use_grade ? '#secupress-schedule' : secupress_admin_url( 'modules', 'schedules#module-scanners' ); ?>
								<li role="presentation">
									<a id="secupress-l-schedule" href="<?php echo $schedule_scan_url; ?>" role="tab" aria-selected="false" aria-controls="secupress-schedule">
										<span class="secupress-label-with-icon">
											<i class="secupress-icon-calendar rounded" aria-hidden="true"></i>
											<span class="secupress-upper"><?php _e( 'Schedule Scans', 'secupress' ); ?></span>
											<span class="secupress-description"><?php _e( 'Manage your recurring scans', 'secupress' ); ?></span>
										</span>
									</a>
								</li>
								<li role="presentation"<?php if ( $use_grade ) { echo 'class="hi dden"'; } ?>>
									<a id="secupress-l-scan" href="#secupress-scan" role="tab" aria-selected="false" aria-controls="secupress-scan" class="secupress-current">
										<span class="secupress-label-with-icon">
											<i class="secupress-icon-secupress" aria-hidden="true"></i>
											<span class="secupress-upper"><?php esc_html_e( 'Scan results', 'secupress' ); ?></span>
											<span class="secupress-primary"><?php echo $last_report; ?></span>
										</span>
									</a>
								</li>
							</ul>
							<div class="secupress-rescan-progress-infos">
								<h3>
									<i class="secupress-icon-secupress" aria-hidden="true"></i><br>

									<?php echo $currently_scanning_text; ?>
								</h3>
							</div>
						</div>
					</div><!-- .secupress-scan-header-main -->
					<?php
				}

				if ( ! $reports ) {
					?>
					<div class="secupress-introduce-first-scan secupress-text-center">
						<h3>
							<i class="secupress-icon-secupress" aria-hidden="true"></i><br>
							<span class="secupress-init-title"><?php _e( 'Click to launch first scan', 'secupress' ); ?></span>

							<?php echo $currently_scanning_text; ?>
						</h3>

						<p class="secupress-start-one-click-scan">
							<button class="secupress-button secupress-button-primary secupress-button-scan" type="button" data-nonce="<?php echo esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ); ?>">
								<span class="icon" aria-hidden="true">
									<i class="secupress-icon-radar"></i>
								</span>
								<span class="text">
									<?php _e( 'Scan my website', 'secupress' ); ?>
								</span>

								<span class="secupress-progressbar-val" style="width:2%;">
									<span class="secupress-progress-val-txt">2 %</span>
								</span>

							</button>
						</p>
					</div><!-- .secupress-introduce-first-scan -->
					<?php
				}
				?>

				<div class="secupress-scanner-steps">
					<?php
					/**
					 * SecuPress Steps work this way:
					 * - current step with li.secupress-current
					 * - passed step(s) with li.secupress-past
					 * - that's all
					 */
					$steps = [
						'1' => [ 'title' => esc_html__( 'Security Report', 'secupress' ) ],
						'2' => [ 'title' => esc_html__( 'Auto-Fix', 'secupress' ) ],
						'3' => [ 'title' => esc_html__( 'Manual Operations', 'secupress' ) ],
						'4' => [ 'title' => esc_html__( 'Resolution Report', 'secupress' ) ],
					];
					$step              = secupress_get_scanner_pagination();
					$steps[2]['state'] = '';
					$steps[3]['state'] = '';
					$steps[4]['state'] = '';

					switch ( $step ) {
						case 1:
							$steps[1]['state'] = ' secupress-current';
						break;
						case 2:
							$steps[1]['state'] = ' secupress-past';
							$steps[2]['state'] = ' secupress-current';
						break;
						case 3:
							$steps[1]['state'] = ' secupress-past';
							$steps[2]['state'] = ' secupress-past';
							$steps[3]['state'] = ' secupress-current';
						break;
						case 4:
							$steps[1]['state'] = ' secupress-past';
							$steps[2]['state'] = ' secupress-past';
							$steps[3]['state'] = ' secupress-past';
							$steps[4]['state'] = ' secupress-current';
						break;
					}
					$current_step_class = 'secupress-is-step-' . $step;
					unset( $step );
					?>
					<ol class="secupress-flex secupress-counter <?php echo esc_attr( $current_step_class ); ?>">
						<?php
						foreach ( $steps as $i => $step ) {
							?>
							<li class="secupress-col-1-3 secupress-counter-put secupress-flex<?php echo $step['state']; ?>" aria-labelledby="sp-step-<?php echo $i; ?>-l" aria-describedby="sp-step-<?php echo $i; ?>-d">
								<span class="secupress-step-name" id="sp-step-<?php echo $i; ?>-l"><?php echo $step['title']; ?></span>
								<?php if ( 3 === $i ) { ?>
									<span class="secupress-step-name alt" aria-hidden="true"><?php echo $steps[4]['title']; ?></span>
								<?php } ?>
							</li>
							<?php
						}
						?>
					</ol>

					<div id="secupress-more-info" class="<?php echo $reports ? ' hide-if-js' : ' secupress-open'; ?>">
						<div class="secupress-flex secupress-flex-top">
							<div class="secupress-col-1-4 step1">
								<div class="secupress-blob">
									<div class="secupress-blob-icon" aria-hidden="true">
										<i class="secupress-icon-radar"></i>
									</div>
									<p class="secupress-blob-title"><?php _e( 'Site Health', 'secupress' ); ?></p>
									<div class="secupress-blob-content" id="sp-step-1-d">
										<p><?php _e( 'Start to check all security items with the Scan your website button.', 'secupress' ); ?></p>
									</div>
								</div>
							</div><!-- .secupress-col-1-4 -->
							<div class="secupress-col-1-4 step2">
								<div class="secupress-blob">
									<div class="secupress-blob-icon" aria-hidden="true">
										<i class="secupress-icon-autofix"></i>
									</div>
									<p class="secupress-blob-title"><?php _e( 'Auto-Fix', 'secupress' ) ?></p>
									<div class="secupress-blob-content" id="sp-step-2-d">
										<p><?php _e( 'Launch the auto-fix on selected issues.', 'secupress' ); ?></p>
									</div>
								</div>
							</div><!-- .secupress-col-1-4 -->
							<div class="secupress-col-1-4 step3">
								<div class="secupress-blob">
									<div class="secupress-blob-icon" aria-hidden="true">
										<i class="secupress-icon-manuals"></i>
									</div>
									<p class="secupress-blob-title"><?php _e( 'Manual Operations', 'secupress' ) ?></p>
									<div class="secupress-blob-content" id="sp-step-3-d">
										<p><?php esc_html_e( 'Go further and take a look at the items you have to fix with specific operations.', 'secupress' ); ?></p>
									</div>
								</div>
							</div><!-- .secupress-col-1-4 -->
							<div class="secupress-col-1-4 step4">
								<div class="secupress-blob">
									<div class="secupress-blob-icon" aria-hidden="true">
										<i class="secupress-icon-pad-check"></i>
									</div>
									<p class="secupress-blob-title"><?php esc_html_e( 'Resolution Report', 'secupress' ); ?></p>
									<div class="secupress-blob-content" id="sp-step-4-d">
										<p><?php esc_html_e( 'Get the new site health report for your website.', 'secupress' ); ?></p>
									</div>
								</div><!-- .secupress-blob -->
							</div><!-- .secupress-col-1-4 -->
						</div><!-- .secupress-flex -->

						<p class="secupress-text-end secupress-m0">
							<a href="#secupress-more-info" class="secupress-link-icon secupress-secupress-icon-right secupress-close-moreinfo<?php echo $reports ? '' : ' dont-trigger-hide'; ?>" data-trigger="slideup" data-target="secupress-more-info">
								<span class="icon" aria-hidden="true">
									<i class="secupress-icon-cross"></i>
								</span>
								<span class="text">
									<?php _e( 'I’ve got it!', 'secupress' ); ?>
								</span>
							</a>
						</p>
					</div><!-- #secupress-more-info -->
				</div><!-- .secupress-scanner-steps -->

			</div><!-- .secupress-section-dark -->

			<div class="secupress-scanner-main-content secupress-section-gray secupress-bordered">

				<div class="secupress-step-content-container">
					<?php
					secupress_scanners_template();
					?>
				</div><!-- .secupress-step-content-container-->

			</div>

			<?php wp_nonce_field( 'secupress_score', 'secupress_score', false ); ?>
		</div>
	</div><!-- .wrap -->
	<?php
}


/** --------------------------------------------------------------------------------------------- */
/** TEMPLATE TAGS =============================================================================== */
/** --------------------------------------------------------------------------------------------- */

/**
 * Print the settings page title.
 *
 * @since 1.0
 *
 * @param (string) $title The title.
 */
function secupress_admin_heading( $title = '' ) {
	$heading_tag = secupress_wp_version_is( '4.3-alpha' ) ? 'h1' : 'h2';
	printf( '<%1$s class="secupress-page-title screen-reader-text">%2$s <sup>%3$s</sup> %4$s</%1$s>', $heading_tag, SECUPRESS_PLUGIN_NAME, SECUPRESS_VERSION, $title );
}

/**
 * Print the dark header of settings pages
 *
 * @since 1.0
 * @author Geoffrey
 *
 * @param (array) $titles The title and subtitle.
 */
function secupress_settings_heading( $titles = array() ) {
	$title    = ! empty( $titles['title'] )    ? $titles['title']    : '';
	$subtitle = ! empty( $titles['subtitle'] ) ? $titles['subtitle'] : '';
	?>
	<div class="secupress-section-dark secupress-settings-header secupress-header-mini secupress-flex">
		<div class="secupress-col-1-3 secupress-col-logo secupress-text-center">
			<div class="secupress-logo-block secupress-flex">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => 131 ) ); ?>
				</div>
				<div class="secupress-lb-name">
					<p class="secupress-lb-title">
					<?php echo secupress_get_logo_word( array( 'width' => 100, 'height' => 24 ) ); ?>
					</p>
				</div>
			</div>
		</div>
		<div class="secupress-col-1-3 secupress-col-text">
			<p class="secupress-text-medium"><?php echo $title; ?></p>
			<?php if ( $subtitle ) { ?>
			<p><?php echo $subtitle; ?></p>
			<?php } ?>
		</div>
		<?php if ( ! secupress_is_white_label() ) { ?>
		<div class="secupress-col-1-3 secupress-col-rateus secupress-text-end">
			<p class="secupress-rateus">
				<strong><?php _e( 'Do you like this plugin?', 'secupress' ) ?></strong>
				<br>
				<?php printf( __( 'Please take a few seconds to rate us on %1$sWordPress.org%2$s', 'secupress' ), '<a target="_blank" title="' . esc_attr__( 'Open in a new window.', 'secupress' ) . '" href="' . SECUPRESS_RATE_URL . '">', '</a>' ); ?>
			</p>
			<p class="secupress-rateus-link">
				<a target="_blank" title="<?php esc_attr_e( 'Open in a new window.', 'secupress' ); ?>" href="<?php echo SECUPRESS_RATE_URL; ?>">
					<i class="secupress-icon-star" aria-hidden="true"></i>
					<i class="secupress-icon-star" aria-hidden="true"></i>
					<i class="secupress-icon-star" aria-hidden="true"></i>
					<i class="secupress-icon-star" aria-hidden="true"></i>
					<i class="secupress-icon-star" aria-hidden="true"></i>
					<span class="screen-reader-text"><?php echo _x( 'Give us five stars', 'hidden text', 'secupress' ); ?></span>
				</a>
			</p>
		</div>
		<?php } ?>
	</div>
	<?php
}


/**
 * Print the scanners page content.
 *
 * @since 1.0
 */
function secupress_scanners_template() {
	secupress_require_class( 'scan' );

	$is_subsite   = is_multisite() && ! is_network_admin();
	$heading_tag  = secupress_wp_version_is( '4.4-alpha' ) ? 'h2' : 'h3';
	// Allowed tags in "Learn more" contents.
	$allowed_tags = array(
		'a'      => array( 'href' => array(), 'title' => array(), 'target' => array() ),
		'abbr'   => array( 'title' => array() ),
		'code'   => array(),
		'em'     => array(),
		'strong' => array(),
		'ul'     => array(),
		'ol'     => array(),
		'li'     => array(),
		'p'      => array(),
		'pre'    => array( 'class' => array() ),
		'br'     => array(),
	);
	// Auto-scans: scans that will be executed on page load.
	$autoscans   = SecuPress_Scan::get_and_delete_autoscans();

	if ( ! $is_subsite ) {
		$secupress_tests = secupress_get_scanners();
		$scanners        = secupress_get_scan_results();
		$fixes           = secupress_get_fix_results();

		// Store the scans in 3 variables. They will be used to order the scans by status: 'bad', 'warning', 'notscannedyet', 'good'.
		$bad_scans     = array();
		$warning_scans = array();
		$good_scans    = array();

		if ( ! empty( $scanners ) ) {
			foreach ( $scanners as $class_name_part => $details ) {
				if ( 'bad' === $details['status'] ) {
					$bad_scans[ $class_name_part ] = $details['status'];
				} elseif ( 'warning' === $details['status'] ) {
					$warning_scans[ $class_name_part ] = $details['status'];
				} elseif ( 'good' === $details['status'] ) {
					$good_scans[ $class_name_part ] = $details['status'];
				}
			}
		}
	} else {
		$secupress_tests = array( secupress_get_tests_for_ms_scanner_fixes() );
		$sites           = secupress_get_results_for_ms_scanner_fixes();
		$site_id         = get_current_blog_id();
		$scanners        = array();
		$fixes           = array();

		foreach ( $sites as $test => $site_data ) {
			if ( ! empty( $site_data[ $site_id ] ) ) {
				$scanners[ $test ] = ! empty( $site_data[ $site_id ]['scan'] ) ? $site_data[ $site_id ]['scan'] : array();
				$fixes[ $test ]    = ! empty( $site_data[ $site_id ]['fix'] )  ? $site_data[ $site_id ]['fix']  : array();
			}
		}
	}

	$step = secupress_get_scanner_pagination();

	switch ( $step ) {
		case 4 :
			require_once( SECUPRESS_INC_PATH . 'admin/scanner-step-4.php' );
			break;
		case 3 :
			require_once( SECUPRESS_INC_PATH . 'admin/scanner-step-3.php' );
			break;
		case 2 :
			require_once( SECUPRESS_INC_PATH . 'admin/scanner-step-2.php' );
			break;
		case 1 :
		default:
			require_once( SECUPRESS_INC_PATH . 'admin/scanner-step-1.php' );
	}
}


/**
 * Print a box with title.
 *
 * @since 1.0
 *
 * @param (array) $args An array containing the box title, content and id.
 */
function secupress_sidebox( $args ) {
	$args = wp_parse_args( $args, array(
		'id'      => '',
		'title'   => 'Missing',
		'content' => 'Missing',
	) );

	echo '<div class="secupress-postbox postbox" id="' . $args['id'] . '">';
		echo '<h3 class="hndle"><span><b>' . $args['title'] . '</b></span></h3>';
		echo'<div class="inside">' . $args['content'] . '</div>';
	echo "</div>\n";
}


/**
 * Will return the current scanner step number.
 *
 * @since 1.0
 * @author Julio Potier
 *
 * @return (int) Returns 1 if first scan never done.
 */
function secupress_get_scanner_pagination() {
	$scans = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );

	if ( empty( $_GET['step'] ) || ! is_numeric( $_GET['step'] ) || empty( $scans ) || 0 > $_GET['step'] ) {
		$step = 1;
	} else {
		$step = (int) $_GET['step'];
		if ( $step > 4 ) {
			secupress_is_jarvis();
		}
	}

	return $step;
}
