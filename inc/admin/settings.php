<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* CSS, JS, FOOTER ============================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( 'admin_enqueue_scripts', '__secupress_add_settings_scripts' );
/**
 * Add some CSS and JS to our settings pages.
 *
 * @since 1.0
 *
 * @param (string) $hook_suffix The current admin page.
 */
function __secupress_add_settings_scripts( $hook_suffix ) {
	global $wp_version;

	$suffix    = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version   = $suffix ? SECUPRESS_VERSION : time();
	$css_depts = array();
	$js_depts  = array( 'jquery' );

	// Sweet Alert.
	if ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_modules' === $hook_suffix || 'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners' === $hook_suffix ) {
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

	wp_localize_script( 'secupress-wordpress-js', 'SecuPressi18n', array( 'isPro' => (int) secupress_is_pro() ) );

	$pages = array(
		'toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners'  => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_modules'  => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' => 1,
		'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_logs'     => 1,
	);

	if ( ! isset( $pages[ $hook_suffix ] ) ) {
		return;
	}

	// SecuPress Common CSS.
	wp_enqueue_style( 'secupress-common-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-common' . $suffix . '.css', array( 'secupress-wordpress-css' ), $version );

	// WordPress Common JS.
	wp_enqueue_script( 'secupress-common-js', SECUPRESS_ADMIN_JS_URL . 'secupress-common' . $suffix . '.js', array( 'secupress-wordpress-js' ), $version, true );

	wp_localize_script( 'secupress-common-js', 'SecuPressi18nCommon', array(
		'confirmText'  => __( 'OK', 'secupress' ),
		'cancelText'   => __( 'Cancel' ),
		'authswal'     => array(
			'title'  => __( 'Authentication', 'secupress' ),
			'email'  => __( 'Enter your email', 'secupress' ),
			'apikey' => __( 'Enter your API Key', 'secupress' ),
			'where'  => __( 'Where can I find my API Key?', 'secupress' ),
			'save'   => __( 'Save and continue to first scan', 'secupress' ),
		),
	) );

	// Settings page.
	if ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_settings' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-settings-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-settings' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}
	// Modules page.
	elseif ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_modules' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-modules-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-modules' . $suffix . '.css', array( 'secupress-common-css' ), $version );

		// JS.
		wp_enqueue_script( 'secupress-modules-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-modules' . $suffix . '.js', array( 'secupress-common-js' ), $version, true );

		$alreadyScanned = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) ) ? 1 : 0;

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
			'backupImpossible'     => __( 'Impossible to backup the database.', 'secupress' ),
			'backupingText'        => __( 'Backuping&hellip;', 'secupress' ),
			'backupedText'         => __( 'Backup done', 'secupress' ),
			// Ban IPs.
			'noBannedIPs'          => __( 'No Banned IPs anymore.', 'secupress' ),
			'IPnotFound'           => __( 'IP not found.', 'secupress' ),
			'IPremoved'            => __( 'IP removed.', 'secupress' ),
			'searchResults'        => _x( 'See search result below.', 'adjective', 'secupress' ),
			'searchReset'          => _x( 'Search reset.', 'adjective', 'secupress' ),
			// First scan.
			'alreadyScanned'       => $alreadyScanned,
			'firstScanText'        => __( 'Before setting modules,<br>launch your first scan.', 'secupress' ),
			'firstScanButton'      => __( 'One Click Scan', 'secupress' ),
			'firstScanURL'         => esc_url( wp_nonce_url( secupress_admin_url( 'scanners' ), 'first_oneclick-scan' ) ) . '&oneclick-scan=1',
			'firstScanImage'       => SECUPRESS_ADMIN_IMAGES_URL . 'icon-radar.png',
			// Expand Textareas
			'expandTextOpen'       => __( 'Show More', 'secupress' ),
			'expandTextClose'      => __( 'Close' ),
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
			'confirmText'        => __( 'OK', 'secupress' ),
			'cancelText'         => __( 'Cancel' ),
			'error'              => __( 'Error', 'secupress' ),
			'fixed'              => __( 'Fixed', 'secupress' ),
			'fixedPartial'       => __( 'Partially fixed', 'secupress' ),
			'notFixed'           => __( 'Not Fixed', 'secupress' ),
			'fixit'              => __( 'Fix it', 'secupress' ),
			'oneManualFix'       => __( 'One fix requires your intervention.', 'secupress' ),
			'someManualFixes'    => __( 'Some fixes require your intervention.', 'secupress' ),
			'spinnerUrl'         => admin_url( 'images/wpspin_light-2x.gif' ),
			'reScan'             => _x( 'Re-Scan', 'verb', 'secupress' ),
			'scanDetails'        => __( 'Scan Details', 'secupress' ),
			'fixDetails'         => __( 'Fix Details', 'secupress' ),
			'supportTitle'       => __( 'Ask for Support', 'secupress' ),
			'supportButton'      => __( 'Open a ticket', 'secupress' ),
			'supportContentFree' => __( '<p>Using the free version you have to post a new thread in the free wordpress.org forums.</p><p><a href="https://wordpress.org/support/plugin/secupress-free#postform" target="_blank" class="secupress-button secupress-button-mini"><span class="icon"><i class="icon-wordpress" aria-hidden="true"></i></span><span class="text">Open the forum</span></a></p><p>When using the Pro version, you can open a ticket directly from this popin: </p><br><p style="text-align:left">Summary: <input class="large-text" type="text" name="summary"></p><p style="text-align:left">Description: <textarea name="description" disabled="disabled">Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page</textarea></p>', 'secupress' ), // ////.
			'supportContentPro'  => '<input type="hidden" id="secupress_support_item" name="secupress_support_item" value=""><p style="text-align:left">Summary: <input class="large-text" type="text" name="summary"></p><p style="text-align:left">Description: <textarea name="description" disabled="disabled">Please provide the specific url(s) where we can see each issue. e.g. the request doesn\'t work on this page: example.com/this-page</textarea></p>', // ////.
		);

		if ( $is_main ) {
			$localize['i18nNonce'] = wp_create_nonce( 'secupress-get-scan-counters' );
		}

		if ( ! empty( $_GET['oneclick-scan'] ) && ! empty( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'first_oneclick-scan' ) && current_user_can( secupress_get_capability() ) ) {
			$times = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );

			if ( ! $times ) {
				$localize['firstOneClickScan'] = 1;
			}
			$_SERVER['REQUEST_URI'] = remove_query_arg( array( '_wpnonce', 'oneclick-scan' ) );
		}

		wp_localize_script( 'secupress-scanner-js', 'SecuPressi18nScanner', $localize );
	}
	// Logs page.
	elseif ( 'secupress_page_' . SECUPRESS_PLUGIN_SLUG . '_logs' === $hook_suffix ) {
		// CSS.
		wp_enqueue_style( 'secupress-logs-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-logs' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}


	// Old WordPress Versions
	// WordPress 3.7 & 3.8
	if ( version_compare( $wp_version, '3.7', '>=' ) && version_compare( $wp_version, '3.9', '<' ) ) {
		wp_enqueue_style( 'secupress-wordpress-3-7',  SECUPRESS_ADMIN_CSS_URL . 'secupress-wordpress-3.7' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}

	// SecuPress version in footer.
	add_filter( 'update_footer', '__secupress_print_version_number_in_footer', 12, 1 );
}


/**
 * Add SecuPress version number next to WP version in footer
 *
 * @since  1.0
 * @author Geoffrey
 *
 * @param (string) $footer Text to print in footer.
 *
 * @return (string)
 */
function __secupress_print_version_number_in_footer( $footer ) {
	return ( $footer ? "$footer | " : '' ) . '<b>' . SECUPRESS_PLUGIN_NAME . ' v.' . SECUPRESS_VERSION . '</b>';
}


/*------------------------------------------------------------------------------------------------*/
/* PLUGINS LIST ================================================================================= */
/*------------------------------------------------------------------------------------------------*/

add_filter( 'plugin_action_links_' . plugin_basename( SECUPRESS_FILE ), '__secupress_settings_action_links' );
/**
 * Add links to the plugin row.
 *
 * @since 1.0
 *
 * @param (array) $actions An array of links.
 *
 * @return (array) The array of links + our links.
 */
function __secupress_settings_action_links( $actions ) {
	if ( ! secupress_is_white_label() ) {
		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http://secupress.me/support/', __( 'Support', 'secupress' ) ) );

		array_unshift( $actions, sprintf( '<a href="%s">%s</a>', 'http://docs.secupress.me', __( 'Docs', 'secupress' ) ) );
	}

	array_unshift( $actions, sprintf( '<a href="%s">%s</a>', esc_url( secupress_admin_url( 'settings' ) ), __( 'Settings' ) ) );

	return $actions;
}


/*------------------------------------------------------------------------------------------------*/
/* ADMIN MENU =================================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_action( ( is_multisite() ? 'network_' : '' ) . 'admin_menu', 'secupress_create_menus' );
/**
 * Create the plugin menu and submenus.
 *
 * @since 1.0
 */
function secupress_create_menus() {
	global $menu;

	// Add a counter of scans with bad result.
	$count = sprintf( ' <span class="update-plugins count-%1$d"><span class="update-count">%1$d</span></span>', secupress_get_scanner_counts( 'bad' ) );
	$cap   = secupress_get_capability();

	// Main menu item.
	add_menu_page( SECUPRESS_PLUGIN_NAME, 'secupress', $cap, SECUPRESS_PLUGIN_SLUG . '_scanners', '__secupress_scanners', 'dashicons-shield-alt' );

	// Sub-menus.
	add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ) . $count, $cap, SECUPRESS_PLUGIN_SLUG . '_scanners', '__secupress_scanners' );
	add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', __( 'Modules', 'secupress' ),  __( 'Modules', 'secupress' ),           $cap, SECUPRESS_PLUGIN_SLUG . '_modules',  '__secupress_modules' );
	add_submenu_page( SECUPRESS_PLUGIN_SLUG . '_scanners', __( 'Settings' ),              __( 'Settings' ),                       $cap, SECUPRESS_PLUGIN_SLUG . '_settings', '__secupress_global_settings' );

	// Fix `add_menu_page()` nonsense.
	end( $menu );
	$key = key( $menu );
	$menu[ $key ][0] = SECUPRESS_PLUGIN_NAME . $count;
}


/*------------------------------------------------------------------------------------------------*/
/* SETTINGS PAGES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Settings page.
 *
 * @since 1.0
 */
function __secupress_global_settings() {
	if ( ! class_exists( 'SecuPress_Settings' ) ) {
		secupress_require_class( 'settings' );
	}

	$class_name = 'SecuPress_Settings_Global';

	if ( ! class_exists( $class_name ) ) {
		secupress_require_class( 'settings', 'global' );
	}

	if ( function_exists( 'secupress_pro_class_path' ) ) {
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
function __secupress_modules() {
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
function __secupress_scanners() {
	$counts  = secupress_get_scanner_counts();
	$times   = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );
	$reports = array();
	$last_pc = -1;

	if ( $times ) {
		foreach ( $times as $time ) {
			$icon = 'right';

			if ( $last_pc > -1 ) {
				if ( $last_pc < $time['percent'] ) {
					$icon = 'up';
				} elseif ( $last_pc > $time['percent'] ) {
					$icon = 'down';
				}
			}

			$last_pc = $time['percent'];

			$reports[] = sprintf(
				'<li data-percent="%1$d">
					<span class="secupress-latest-list-time timeago">%4$s</span>
					<span class="secupress-latest-list-date">%5$s</span>
					<strong class="secupress-latest-list-grade letter l%3$s">%3$s</strong>
					<i class="dashicons mini dashicons-arrow-%2$s-alt2" aria-hidden="true"></i>
				</li>',
				$time['percent'],
				$icon,
				$time['grade'],
				sprintf( __( '%s ago' ), human_time_diff( $time['time'] ) ),
				date_i18n( _x( 'M dS, Y \a\t h:ia', 'Latest scans', 'secupress' ), $time['time'] )
			);
		}

		$reports = array_reverse( $reports );
	}
	?>
	<div class="wrap">

		<?php secupress_admin_heading( __( 'Scanners', 'secupress' ) ); ?>
		<div class="secupress-wrapper">
			<div class="secupress-section-dark secupress-scanners-header<?php echo $times ? '' : ' secupress-not-scanned-yet'; ?>">
				
				<div class="secupress-heading secupress-flex secupress-flex-spaced secupress-wrap">
					<p class="secupress-text-medium"><?php 
						/* translators: %s is the plugin name */
						printf( esc_html__( 'Welcome to %s the best way to secure your website!', 'secupress' ), SECUPRESS_PLUGIN_NAME );
					?></p>
					<p class="secupress-text-end hide-if-no-js">
						<a href="#secupress-more-info" class="secupress-link-icon secupress-open-moreinfo" data-trigger="slidedown" data-target="secupress-more-info">
							<span class="icon">
								<i class="icon-info" aria-hidden="true"></i>
							</span>
							<span class="text">
								<?php esc_html_e( 'How does it work?', 'secupress' ); ?>
							</span>
						</a>
					</p>

					<div id="secupress-more-info" class="secupress-full-wide secupress-counter">
						<div class="secupress-flex secupress-flex-top">
							<div class="secupress-col-1-3">
								<div class="secupress-blob secupress-counter-put">
									<div class="secupress-blob-icon">
										<i class="icon-radar" aria-hidden="true"></i>
									</div>
									<div class="secupress-blob-content">
										<p><?php esc_html_e( 'Start a checking of all security points with the One Click Scan button.', 'secupress' ); ?></p>
									</div>
								</div>
							</div>
							<div class="secupress-col-1-3">
								<div class="secupress-blob secupress-counter-put">
									<div class="secupress-blob-icon">
										<i class="icon-pad-list" aria-hidden="true"></i>
									</div>
									<div class="secupress-blob-content">
										<p><?php esc_html_e( 'Take a look at validated points and points you have to fix.', 'secupress' ); ?></p>
									</div>
								</div>
							</div>
							<div class="secupress-col-1-3">
								<div class="secupress-blob secupress-counter-put">
									<div class="secupress-blob-icon">
										<i class="icon-pad-check" aria-hidden="true"></i>
									</div>
									<div class="secupress-blob-content">
										<p><?php esc_html_e( 'Fix all points automatically with the One Click Fix button or do it manually if you are a warrior.', 'secupress' ); ?></p>
									</div>
								</div>
							</div>
						</div>

						<p class="secupress-text-end secupress-m0">
							<a href="#secupress-more-info" class="secupress-link-icon secupress-icon-right secupress-close-moreinfo" data-trigger="slideup" data-target="secupress-more-info">
								<span class="icon">
									<i class="icon-cross" aria-hidden="true"></i>
								</span>
								<span class="text">
									<?php esc_html_e( 'I\'ve got it!', 'secupress' ); ?>
								</span>
							</a>
						</p>
					</div>
				</div>

				<ul class="secupress-flex secupress-tabs secupress-light-tabs" role="tablist" data-content="#sp-tab-scans">
					<li role="presentation">
						<a id="secupress-l-scan" href="#secupress-scan" role="tab" aria-selected="true" aria-controls="secupress-scan" class="secupress-current">
							<i class="icon-radar" aria-hidden="true"></i>
							<?php esc_html_e( 'Scan Security Points', 'secupress' ); ?>
						</a>
					</li>
					<li role="presentation">
						<a id="secupress-l-latest" href="#secupress-latest" role="tab" aria-selected="false" aria-controls="secupress-latest">
							<i class="icon-back" aria-hidden="true"></i>
							<?php esc_html_e( 'Latest Scans', 'secupress' ); ?>
						</a>
					</li>
					<li role="presentation">
						<a id="secupress-l-schedule" href="#secupress-schedule" role="tab" aria-selected="false" aria-controls="secupress-schedule">
							<i class="icon-calendar" aria-hidden="true"></i>
							<?php esc_html_e( 'Schedule Scans', 'secupress' ); ?>
						</a>
					</li>
				</ul>

				<div id="sp-tab-scans" class="secupress-tabs-contents">
					<div id="secupress-scan" class="secupress-tab-content" role="tabpanel" aria-labelledby="secupress-l-scan">
						<div class="secupress-flex secupress-row">
							<div class="secupress-flex secupress-chart">

								<div class="secupress-chart-container">
									<canvas class="secupress-chartjs" id="status_chart" width="197" height="197"></canvas>
									<div class="secupress-score"><?php echo $counts['letter']; ?></div>
								</div>

								<ul class="secupress-chart-legend">
									<li class="status-good" data-status="good">
										<span class="secupress-carret"></span>
										<?php esc_html_e( 'Good', 'secupress' ); ?>
										<span class="secupress-count-good"></span>
									</li>
									<li class="status-bad" data-status="bad">
										<span class="secupress-carret"></span>
										<?php esc_html_e( 'Bad', 'secupress' ); ?>
										<span class="secupress-count-bad"></span>
									</li>
									<li class="status-warning" data-status="warning">
										<span class="secupress-carret"></span>
										<?php esc_html_e( 'Warning', 'secupress' ); ?>
										<span class="secupress-count-warning"></span>
									</li>
									<?php if ( $counts['notscannedyet'] ) : ?>
									<li class="status-notscannedyet" data-status="notscannedyet">
										<span class="secupress-carret"></span>
										<?php esc_html_e( 'New Scan', 'secupress' ); ?>
										<span class="secupress-count-notscannedyet"></span>
									</li>
									<?php endif; ?>
								</ul><!-- .secupress-chart-legend -->
							</div><!-- .secupress-chart.secupress-flex -->

							<div class="secupress-scan-infos">
								<p class="secupress-score-text secupress-text-big secupress-m0">
									<?php echo $counts['text']; ?>
								</p>
								<p class="secupress-score secupress-score-subtext secupress-m0"><?php echo $counts['subtext']; ?></p>

								<p class="secupress-actions-line">
									<button class="secupress-button button-secupress-scan" type="button" data-nonce="<?php echo esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ); ?>">
										<span class="icon">
											<i class="icon-radar" aria-hidden="true"></i>
										</span>
										<span class="text">
											<?php _e( 'One Click Scan', 'secupress' ); ?>
										</span>
									</button>

									<button class="secupress-button-primary button-secupress-fix" type="button">
										<span class="icon">
											<i class="icon-shield" aria-hidden="true"></i>
										</span>
										<span class="text">
											<?php _e( 'One Click Fix', 'secupress' ); ?>
										</span>
									</button>
								</p>

								<div id="tweeterA" class="hidden">
										<i><?php
											/* translators: %s is the plugin name */
											printf( esc_html__( 'Wow! My website just got an A security grade using %s, what about yours?', 'secupress' ), SECUPRESS_PLUGIN_NAME );
										?></i>

										<a class="button button-small" href="https://twitter.com/intent/tweet?via=secupress&amp;url=<?php
											/* translators: %s is the plugin name */
											echo urlencode( esc_url_raw( 'http://secupress.fr&text=' . sprintf( __( 'Wow! My website just got an A security grade using %s, what about yours?', 'secupress' ), SECUPRESS_PLUGIN_NAME ) ) );
										?>">
											<span class="icon"><span class="dashicons dashicons-twitter"></span></span>
											<span class="text"><?php esc_html_e( 'Tweet that', 'secupress' ); ?></span>
										</a>
								</div>
							</div>

						</div><!-- .secupress-flex -->
					</div><!-- .secupress-tab-content -->

					<div id="secupress-latest" class="secupress-tab-content" role="tabpanel" aria-labelledby="secupress-l-latest">
						<div class="secupress-flex secupress-flex-top">
							<div class="secupress-latest-chart">
								<p class="secupress-text-medium">
									<?php esc_html_e( 'Latest Scans', 'secupress' ); ?>
								</p>
								<div class="secupress-flex">
									<div class="secupress-chart-container">
										<canvas class="secupress-chartjs" id="status_chart_mini" width="127" height="127"></canvas>
										<div class="secupress-score"><?php echo $counts['letter']; ?></div>
									</div>
									<ul class="secupress-chart-legend">
										<li class="status-good" data-status="good">
											<span class="secupress-carret"></span>
											<?php esc_html_e( 'Good', 'secupress' ); ?>
											<span class="secupress-count-good"></span>
										</li>
										<li class="status-bad" data-status="bad">
											<span class="secupress-carret"></span>
											<?php esc_html_e( 'Bad', 'secupress' ); ?>
											<span class="secupress-count-bad"></span>
										</li>
										<li class="status-warning" data-status="warning">
											<span class="secupress-carret"></span>
											<?php esc_html_e( 'Warning', 'secupress' ); ?>
											<span class="secupress-count-warning"></span>
										</li>
										<?php if ( $counts['notscannedyet'] ) : ?>
										<li class="status-notscannedyet" data-status="notscannedyet">
											<span class="secupress-carret"></span>
											<?php esc_html_e( 'New Scan', 'secupress' ); ?>
											<span class="secupress-count-notscannedyet"></span>
										</li>
										<?php endif; ?>
									</ul><!-- .secupress-chart-legend -->
								</div>
							</div>
							<div class="secupress-latest-title">
								<p class="secupress-text-medium">
									<?php _e( 'Your last 5<br>one click scans', 'secupress' ); ?>
								</p>
							</div>
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
							</div>
						</div><!-- .secupress-flex -->
					</div><!-- .secupress-tab-content -->

					<div id="secupress-schedule" class="secupress-tab-content secupress-text-center" role="tabpanel" aria-labelledby="secupress-l-schedule">
						<p class="secupress-text-medium">
							<?php esc_html_e( 'Schedule your security analysis', 'secupress' ); ?>
						</p>
						<p><?php _e('The analysis of security points is keeping updated. No need to connect to your back office with our automatic scan.', 'secupress' ); ?></p>

						<?php
						/////
						$last_schedule = '1463654935';
						$next_schedule = '1464654935';

						if ( secupress_is_pro() ) {
						?>
						<div class="secupress-schedules-infos is-pro">						
							<p class="secupress-flex secupress-ib">
								<i class="icon-clock-o" aria-hidden="true"></i>
								<span><?php printf( __( 'Last automatic scan: %s', 'secupress' ), date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress'), $last_schedule ) ); ?></span>
							</p>
							<p class="secupress-flex secupress-ib next-one">
								<i class="icon-clock-o" aria-hidden="true"></i>
								<span><?php printf( __( 'Next automatic scan: %s', 'secupress' ), date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress'), $next_schedule ) ); ?></span>
							</p>

							<p class="secupress-cta">
								<a href="#" class="secupress-button secupress-button-primary"><?php esc_html_e( 'Schedule your next analysis', 'secupress' ); ?></a>
							</p>
							
						<?php } else { ?>
						<div class="secupress-schedules-infos">
							<p class="secupress-flex secupress-ib">
								<i class="icon-clock-o" aria-hidden="true"></i>
								<span><?php printf( __( 'Last automatic scan: %s', 'secupress' ), date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress'), $last_schedule ) ); ?></span>
							</p>
							<p class="secupress-flex secupress-ib next-one">
								<i class="icon-clock-o" aria-hidden="true"></i>
								<span><?php printf( __( 'Next automatic scan: %s', 'secupress' ), date_i18n( _x( 'Y-m-d \a\t h:ia', 'Schedule date', 'secupress'), $next_schedule ) ); ?></span>
							</p>

							<p class="secupress-cta">
								<a href="#" class="secupress-button secupress-button-tertiary"><?php esc_html_e( 'Schedule your next analysis', 'secupress' ); ?></a>
							</p>
							<p class="secupress-cta-detail"><?php _e( 'Available with pro version', 'secupress' ); ?></p>

						<?php } ?>

						</div><!-- .secupress-schedules-infos -->

					</div><!-- .secupress-tab-content -->

				</div><!-- .secupress-tabs-contents -->

				<div class="secupress-before-caroupoivre">
					<h3><?php esc_html_e( 'To begin, start your first scan', 'secupress' ); ?></h3>
					<p><?php esc_html_e( 'It\'s easy, just click on the button below.', 'secupress' ); ?></p>

					<p class="secupress-start-one-click-scan">
						<button class="secupress-button secupress-button-primary button-secupress-scan" type="button" data-nonce="<?php echo esc_attr( wp_create_nonce( 'secupress-update-oneclick-scan-date' ) ); ?>">
							<span class="icon">
								<i class="icon-radar" aria-hidden="true"></i>
							</span>
							<span class="text">
								<?php esc_html_e( 'One Click Scan', 'secupress' ); ?>
							</span>
						</button>
					</p>
				</div>
				<div class="secupress-one-click-scanning-slideshow hidden">
					<div class="secupress-caroupoivre">
						<div id="secupress-slide1" class="secupress-slide"></div>

						<?php if ( ! secupress_is_pro() ) : // Trad fr + wording ////. ?>
						<div id="secupress-slide2" class="secupress-slide secupress-slide-pro">
							<h3 class="slide-title"><?php _e( 'Passez à la version pro', 'secupress' ); ?></h3>
							<p class="slide-text"><?php _e( 'Support premium, accès à tous les modules, lorem ipsum.', 'secupress' ); ?></p>
						</div>
						<?php else : ?>
						<div id="secupress-slide2" class="secupress-slide secupress-slide-pro">
							<h3 class="slide-title"><?php _e( 'Programmez vos analyses de sécurité', 'secupress' ); ?></h3>
							<p class="slide-text"><?php _e( 'L\'analyse des points reste à jour, sans vous connectez au back office avec le scan automatique.', 'secupress' ); ?></p>
						</div>
						<?php endif; ?>
						
						<!-- Available slides, random picked in JS -->
						<div class="secupress-slide secupress-slide-1">
							<h3 class="slide-title"><?php _e( 'Une gamme de modules à votre service', 'secupress' ); ?></h3>
							<p><?php _e( 'Allez plus loin dans la sécurisation de votre site avec nos modules et activez les fonctionnalités complémentaires.', 'secupress' ); ?></p>
						</div>
						<div class="secupress-slide secupress-slide-2">
							<h3 class="slide-title"><?php _e( 'Sécurisez votre site WordPress simplement', 'secupress' ); ?></h3>
							<p class="slide-text"><?php _e( 'En un écran, visualisez les points de sécurité Bons ou Mauvais et utilisez le bouton <strong>One Click Fix</strong> pour les corriger rapidement.', 'secupress' ); ?></p>
						</div>
					</div><!-- .secupress-caroupoivre -->

					<div class="secupress-progressbar">
						<div class="secupress-progressbar-val">
							<span class="secupress-progress-val-txt">0 %</span>
						</div>
					</div>
				</div><!-- .secupress-one-click-scanning-slideshow -->

				<ul id="secupress-type-filters" class="secupress-big-tabs secupress-tabs secupress-flex secupress-text-start hide-if-no-js" role="tablist">
					<?php
					if ( $counts['notscannedyet'] ) {
						$tabs        = array( 'notscannedyet' => esc_html__( 'New', 'secupress' ) );
						$default_tab = 'notscannedyet';
					} else {
						$tabs        = array();
						$default_tab = 'bad';
					}

					if ( ! is_multisite() || is_network_admin() ) {
						$tabs['hasaction'] = esc_html__( 'Action needed', 'secupress' );
					}

					$tabs = array_merge( $tabs, array(
						'bad'     => esc_html__( 'Bad', 'secupress' ),
						'warning' => esc_html__( 'Warning', 'secupress' ),
						'good'    => esc_html__( 'Good', 'secupress' ),
					) );

					foreach ( $tabs as $slug => $name ) :
						$is_hidden = 'hasaction' === $slug && ! $counts[ $slug ];
						?>
						<li class="secupress-big-tab-<?php echo $slug; ?><?php echo $is_hidden ? ' hidden' : ''; ?>"<?php echo $is_hidden ? ' aria-hidden="true"' : ''; ?> role="presentation">
							<a href="#tab-<?php echo $slug; ?>" aria-controls="tab-<?php echo $slug; ?>" role="tab"<?php echo $default_tab === $slug ? ' class="secupress-current"' : ''; ?> data-type="<?php echo $slug; ?>">
								<span class="secupress-tab-title"><?php echo $name; ?></span>
								<span class="secupress-tab-subtitle"><?php printf( _n( '%d issue', '%d issues', $counts[ $slug ], 'secupress' ), $counts[ $slug ] ); ?></span>
							</a>
						</li>
					<?php endforeach; ?>
				</ul>
			</div><!-- .secupress-section-dark -->

			<div class="secupress-section-gray secupress-scanners-filters secupress-bordered-lat">
				<div class="secupress-flex-spaced secupress-wrap">
					<div>
						<p class="secupress-text-basup secupress-bold secupress-m0"><?php esc_html_e( 'List of analyzed security points', 'secupress' ); ?></p>
						<p class="secupress-m0 secupress-gray"><?php esc_html_e( 'These issues should be fixed right now!', 'secupress' ); ?></p>
					</div>
					<div id="secupress-priority-filters" class="hide-if-no-js">
						<p class="secupress-childs-ib secupress-ib-spaced secupress-gray-medium">
							<span class="secupress-gray"><?php esc_html_e( 'Filter by priority', 'secupress' ); ?></span>
							<span>
								<input id="filter-high" type="checkbox" class="secupress-checkbox" name="high" checked="checked">
								<label for="filter-high"><?php esc_html_e( 'High', 'secupress' ); ?></label>
							</span>
							<span>
								<input id="filter-medium" type="checkbox" class="secupress-checkbox" name="medium" checked="checked">
								<label for="filter-medium"><?php esc_html_e( 'Medium', 'secupress' ); ?></label>
							</span>
							<span>
								<input id="filter-low" type="checkbox" class="secupress-checkbox" name="low" checked="checked">
								<label for="filter-low"><?php esc_html_e( 'Low', 'secupress' ); ?></label>
							</span>
						</p>
					</div>
				</div>
			</div>
			<div class="secupress-section-light secupress-scanners-list secupress-bordered-lat secupress-lined-b secupress-pt1p">
				<?php secupress_scanners_template(); ?>
			</div>

			<?php wp_nonce_field( 'secupress_score', 'secupress_score', false ); ?>
		</div>
	</div><!-- .wrap -->
	<?php
}


/*------------------------------------------------------------------------------------------------*/
/* TEMPLATE TAGS ================================================================================ */
/*------------------------------------------------------------------------------------------------*/

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
 * @param (array) $titles The title and subtitle
 */
function secupress_settings_heading( $titles = array() ) {
	extract( $titles );
?>
	<div class="secupress-section-dark secupress-settings-header secupress-header-mini secupress-flex">
		<div class="secupress-col-1-3 secupress-col-logo secupress-text-center">
			<div class="secupress-logo-block secupress-flex">
				<div class="secupress-lb-logo">
					<?php echo secupress_get_logo( array( 'width' => 131 ) ); ?>
				</div>
				<div class="secupress-lb-name">
					<p class="secupress-lb-title"><?php echo SECUPRESS_PLUGIN_NAME; ?></p>
				</div>
			</div>
		</div>
		<div class="secupress-col-1-3 secupress-col-text">
			<p class="secupress-text-medium"><?php echo $title; ?></p>
			<?php if ( isset( $subtitle ) ) { ?>
			<p><?php echo $subtitle; ?></p>
			<?php } ?>
		</div>
		<div class="secupress-col-1-3 secupress-col-rateus secupress-text-end">
			<p class="secupress-rateus">
				<strong><?php _e('You like this plugin?') ?></strong>
				<br>
				<?php printf( __( 'Please take a few seconds to rate us on %sWordPress.org%s', 'secupress' ), '<a href="' . SECUPRESS_RATE_URL . '">', '</a>' ); ?>
			</p>
			<p class="secupress-rateus-link">
				<a href="<?php echo SECUPRESS_RATE_URL; ?>">
					<i class="icon-star" aria-hidden="true"></i>
					<i class="icon-star" aria-hidden="true"></i>
					<i class="icon-star" aria-hidden="true"></i>
					<i class="icon-star" aria-hidden="true"></i>
					<i class="icon-star" aria-hidden="true"></i>
					<span class="screen-reader-text"><?php echo _x( 'Give us a five stars', 'hidden text', 'secupress' ); ?></span>
				</a>
			</p>
		</div>
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
		'a'      => array( 'href' => array(),'title' => array(), 'target' => array() ),
		'abbr'   => array( 'title' => array() ),
		'code'   => array(),
		'em'     => array(),
		'strong' => array(),
		'ul'     => array(),
		'ol'     => array(),
		'li'     => array(),
		'p'      => array(),
		'br'     => array(),
	);
	// Actions the user needs to perform for a fix.
	$fix_actions = SecuPress_Scan::get_and_delete_fix_actions();
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
	?>
	<div id="secupress-tests">
		<?php
		foreach ( $secupress_tests as $prio_key => $class_name_parts ) {
			$i = 0;
			?>
			<div class="secupress-table-prio-all<?php echo ( $is_subsite ? '' : ' secupress-table-prio-' . $prio_key ); ?>">

				<?php
				if ( ! $is_subsite ) {
					$prio_data = SecuPress_Scan::get_priorities( $prio_key );
				?>
				<div class="secupress-prio-title prio-<?php echo $prio_key; ?>">
					<?php echo '<' . $heading_tag . ' class="secupress-prio-h" title="' . $prio_data['description'] . '">' . $prio_data['title'] . '</' . $heading_tag . '>'; ?>
				</div>

				<?php
				}

				$class_name_parts = array_combine( array_map( 'strtolower', $class_name_parts ), $class_name_parts );

				if ( ! $is_subsite ) {
					foreach ( $class_name_parts as $option_name => $class_name_part ) {
						if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
							unset( $class_name_parts[ $option_name ] );
							continue;
						}

						secupress_require_class( 'scan', $class_name_part );
					}

					// For this priority, order the scans by status: 'bad', 'warning', 'notscannedyet', 'good'.
					$this_prio_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
					$this_prio_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
					$this_prio_good_scans    = array_intersect_key( $class_name_parts, $good_scans );
					$class_name_parts        = array_diff_key( $class_name_parts, $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );
					$class_name_parts        = array_merge( $this_prio_bad_scans, $this_prio_warning_scans, $class_name_parts, $this_prio_good_scans );
					unset( $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );
				} else {
					foreach ( $class_name_parts as $option_name => $class_name_part ) {
						// Display only scanners where we have a scan result or a fix to be done.
						if ( empty( $scanners[ $option_name ] ) && empty( $fixes[ $option_name ] ) || ! file_exists( secupress_class_path( 'scan', $option_name ) ) ) {
							unset( $class_name_parts[ $option_name ] );
							continue;
						}

						secupress_require_class( 'scan', $class_name_part );
					}
				}

				// Print the rows.
				foreach ( $class_name_parts as $option_name => $class_name_part ) {
					++$i;
					$class_name   = 'SecuPress_Scan_' . $class_name_part;
					$current_test = $class_name::get_instance();
					$referer      = urlencode( esc_url_raw( self_admin_url( 'admin.php?page=' . SECUPRESS_PLUGIN_SLUG . '_scanners' . ( $is_subsite ? '' : '#' . $class_name_part ) ) ) );
					$css_class    = ' type-' . sanitize_key( $class_name::$type );

					if ( $is_subsite ) {
						$css_class .= 0 === $i % 2 ? '' : ' alternate';
					} else {
						$css_class .= 0 === $i % 2 ? ' alternate-2' : ' alternate-1';
					}

					// Scan.
					$scanners[ $option_name ]           = isset( $scanners[ $option_name ] )             ? $scanners[ $option_name ]           : array();
					$scanners[ $option_name ]['status'] = ! empty( $scanners[ $option_name ]['status'] ) ? $scanners[ $option_name ]['status'] : 'notscannedyet';

					$status_text  = secupress_status( $scanners[ $option_name ]['status'] );
					$status_class = ! empty( $scanners[ $option_name ]['status'] ) ? sanitize_html_class( $scanners[ $option_name ]['status'] ) : 'notscannedyet';
					$scan_nonce   = 'secupress_scanner_' . $class_name_part . ( $is_subsite ? '-' . $site_id : '' );
					$scan_nonce   = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part . '&_wp_http_referer=' . $referer . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) ), $scan_nonce );
					$css_class   .= ' status-' . $status_class;
					$css_class   .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
					$css_class   .= false === $current_test::$fixable || 'pro' === $current_test::$fixable && ! secupress_is_pro() ? ' not-fixable' : '';
					$css_class   .= ! empty( $fixes[ $option_name ]['has_action'] ) ? ' status-hasaction' : '';

					if ( ! empty( $scanners[ $option_name ]['msgs'] ) ) {
						$scan_message = secupress_format_message( $scanners[ $option_name ]['msgs'], $class_name_part );
					} else {
						$scan_message = '&#175;';
					}

					// Fix.
					$fix_status_text  = ! empty( $fixes[ $option_name ]['status'] ) && 'good' !== $fixes[ $option_name ]['status'] ? secupress_status( $fixes[ $option_name ]['status'] ) : '';
					$fix_css_class    = ! empty( $fixes[ $option_name ]['status'] ) ? ' status-' . sanitize_html_class( $fixes[ $option_name ]['status'] ) : ' status-cantfix';
					$fix_action       = 'secupress_fixit_' . $class_name_part . ( $is_subsite ? '-' . $site_id : '' );
					$fix_nonce_url    = wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part . '&_wp_http_referer=' . $referer . ( $is_subsite ? '&for-current-site=1&site=' . $site_id : '' ) ), $fix_action );

					if ( ! empty( $fixes[ $option_name ]['msgs'] ) && 'good' !== $status_class ) {
						$fix_message = secupress_format_message( $fixes[ $option_name ]['msgs'], $class_name_part );
					} else {
						$fix_message = '';
					}
					?>
					<div id="<?php echo $class_name_part; ?>" class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all<?php echo $css_class; ?>">

						<div class="secupress-flex secupress-flex-top secupress-flex-spaced">
							<div class="secupress-item-header">
								<p class="secupress-item-title"><?php echo $class_name::$title; ?></p>
								<div class="secupress-row-actions">
									<span class="hide-if-no-js">
										<button type="button" class="secupress-details link-like" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get details', 'secupress' ); ?>">
											<span class="icon">
												<i class="icon-info-disk" aria-hidden="true"></i>
											</span>
											<span class="text">
												<?php _e( 'Learn more', 'secupress' ); ?>
											</span>
										</button>
									</span>
								</div>
							</div><!-- .secupress-item-header -->
							<div class="secupress-item-actions-fix">
								<div class="secupress-fix-status-text"><?php echo $fix_status_text; ?></div>

								<div class="secupress-fix-status-actions">
								<?php
								if ( true === $current_test::$fixable || 'pro' === $current_test::$fixable && secupress_is_pro() ) {
									?>
									<a class="secupress-button-primary secupress-button-mini secupress-fixit<?php echo $current_test::$delayed_fix ? ' delayed-fix' : '' ?>" href="<?php echo esc_url( $fix_nonce_url ); ?>">
										<span class="icon">
											<i class="icon-shield" aria-hidden="true"></i>
										</span>
										<span class="text">
											<?php _e( 'Fix it', 'secupress' ); ?>
										</span>
									</a>
									<div class="secupress-row-actions">
										<span class="hide-if-no-js">
											<button type="button" class="secupress-details-fix link-like" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get fix details', 'secupress' ); ?>">
													<?php _e( 'How?', 'secupress' ); ?>
											</button>
										</span>
									</div>
									<?php
								} elseif ( 'pro' === $current_test::$fixable ) { // //// #.
									?>
									<button type="button" class="secupress-button-primary secupress-button-mini secupress-go-pro">
										<?php esc_html_e( 'Fix it with Pro', 'secupress' ); ?>
										<i class="icon-secupress-simple" aria-hidden="true"></i>
									</button>
									<?php
								} else { // Really not fixable by the plugin.
								?>
									<em class="secupress-gray">
									<?php esc_html_e( 'Cannot be fixed automatically.', 'secupress' ); ?>
									</em>
									<span class="hide-if-no-js">
										<button type="button" class="secupress-details-fix secupress-button secupress-button-mini secupress-button-primary secupress-button-ghost" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get fix details', 'secupress' ); ?>">
											<span class="icon">
												<i class="icon-shield" aria-hidden="true"></i>
											</span>
											<span class="text">
												<?php _e( 'How to fix?', 'secupress' ); ?>
											</span>
										</button>
									</span>
								<?php
								}
								?>
								</div><!-- .secupress-fix-status-actions -->
							</div>
						</div><!-- .secupress-flex -->

						<div class="secupress-flex secupress-flex-spaced secupress-scan-result-n-actions">
							<div class="secupress-scan-result">
								<div class="secupress-scan-message">
									<?php echo $scan_message; ?>
								</div>
							</div>
							<div class="secupress-scan-actions">
								<p>
									<a class="secupress-button secupress-button-mini secupress-scanit" href="<?php echo esc_url( $scan_nonce ); ?>">
										<span class="icon">
											<i class="icon-refresh" aria-hidden="true"></i>
										</span>
										<span class="text">
											<?php echo 'notscannedyet' === $scanners[ $option_name ]['status'] ? _x( 'Scan', 'verb', 'secupress' ) : _x( 'Re-Scan', 'verb', 'secupress' ); ?>
										</span>
									</a>
								</p>
							</div>
						</div>

						<div class="secupress-flex secupress-flex-spaced secupress-fix-result secupress-bg-gray">
							<div class="secupress-fix-result-message">
								<?php echo $fix_message; ?>
							</div>
							<?php
							if ( true === $current_test::$fixable || 'notscannedyet' !== $scanners[ $option_name ]['status'] || ( 'pro' !== $current_test::$fixable || secupress_is_pro() ) ) { ?>
							<div class="secupress-fix-result-retryfix hidden">
								<a href="<?php echo esc_url( $fix_nonce_url ); ?>" class="secupress-button secupress-button-primary secupress-button-mini">
									<span class="icon">
										<i class="icon-shield"></i>
									</span>
									<span class="text">
										<?php esc_html_e( 'Retry to fix', 'secupress' ); ?>
									</span>
								</a>
							</div>
							<?php } ?>
						</div>
						<?php // TODO: Make it appears dynamically ////. ?>
						<div class="secupress-fix-result-actions secupress-bg-gray">
								<p>
									<a href="#" class="secupress-button secupress-button-mini">
										<span class="icon">
											<i class="icon-file-text"></i>
										</span>
										<span class="text">
											<?php esc_html_e( 'Read the documentation', 'secupress' ); ?>
										</span>
									</a>
									<?php
									$support_href   = secupress_is_pro() ? 'http://secupress.me/support/?item=' . $option_name : 'https://wordpress.org/support/plugin/secupress-free#postform'; // Correct slug on repo? ////.
									$support_suffix = secupress_is_pro() ? 'pro' : 'free';
									?>
									<a href="<?php echo $support_href; ?>" class="secupress-button secupress-button-mini secupress-ask-support secupress-ask-support-<?php echo $support_suffix; ?>">
										<span class="icon">
											<i class="icon-ask"></i>
										</span>
										<span class="text">
											<?php esc_html_e( 'Ask support about it', 'secupress' ); ?>
										</span>
									</a>
								</p>
						</div>

						<?php // Hidden items used for Sweet Alerts. ?>
						<div id="details-<?php echo $class_name_part; ?>" class="details hide-if-js">
							<?php _e( 'Scan Details: ', 'secupress' ); ?>
							<span class="details-content"><?php echo wp_kses( $current_test::$more, $allowed_tags ); ?></span>
						</div>
						<div id="details-fix-<?php echo $class_name_part; ?>" class="details hide-if-js">

							<?php _e( 'Fix Details: ', 'secupress' ); ?>
							<span class="details-content"><?php echo wp_kses( $current_test::$more_fix, $allowed_tags ); ?></span>
						</div>

					</div><!-- </tr> -->

					<?php
					if ( $class_name_part === $fix_actions[0] ) {
						$fix_actions = explode( ',', $fix_actions[1] );
						$fix_actions = array_combine( $fix_actions, $fix_actions );
						$fix_actions = $current_test->get_required_fix_action_template_parts( $fix_actions );

						if ( $fix_actions ) { ?>
							<div class="test-fix-action">
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<h3><?php echo _n( 'This action requires your attention', 'These actions require your attention', count( $fix_actions ), 'secupress' ); ?></h3>
									<?php
									echo implode( '', $fix_actions );
									echo '<p class="submit"><button type="submit" name="submit" class="secupress-button secupress-button-primary">' . __( 'Fix it', 'secupress' ) . "</button></p>\n";
									$current_test->for_current_site( $is_subsite )->get_fix_action_fields( array_keys( $fix_actions ) );
									?>
								</form>
							</div>
							<?php
						}

						$fix_actions = array( 0 => false );
					}
				}
				?>

			</div>
			<?php
		} // foreach prio
		?>
	</div><!-- #secupress-tests -->
	<?php
}


/**
 * Get a scan or fix status, formatted with icon and human readable text.
 *
 * @since 1.0
 *
 * @param (string) $status The status code.
 *
 * @return (string) Formatted status.
 */
function secupress_status( $status ) {
	$template = '<span class="dashicons dashicons-shield-alt secupress-dashicon" aria-hidden="true"></span> %s';

	switch ( $status ) :
		case 'bad':
			return wp_sprintf( $template, __( 'Bad', 'secupress' ) );
		case 'good':
			return wp_sprintf( $template, __( 'Good', 'secupress' ) );
		case 'warning':
			return wp_sprintf( $template, __( 'Warning', 'secupress' ) );
		case 'cantfix':
			return '';
		default:
			return wp_sprintf( $template, __( 'New Scan', 'secupress' ) );
	endswitch;
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
