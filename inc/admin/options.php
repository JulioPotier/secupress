<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* OPTION REGISTRATION ========================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Whitelist our global settings.
 *
 * @since 1.0
 */
add_action( 'admin_init', 'secupress_register_global_setting' );

function secupress_register_global_setting() {
	secupress_register_setting( 'global', SECUPRESS_SETTINGS_SLUG );
}


/**
 * Sanitize our global settings.
 *
 * @since 1.0
 */
function __secupress_global_settings_callback( $value ) {
	$value = $value ? $value : array();

	if ( isset( $value['sanitized'] ) ) {
		return $value;
	}
	$value['sanitized'] = 1;

	// License validation
	$value['consumer_email'] = ! empty( $value['consumer_email'] ) ? sanitize_email( $value['consumer_email'] )    : '';
	$value['consumer_key']   = ! empty( $value['consumer_key'] )   ? sanitize_text_field( $value['consumer_key'] ) : '';

	if ( $value['consumer_email'] && $value['consumer_key'] ) {
		$response = wp_remote_post( SECUPRESS_WEB_DEMO . 'valid_key.php',
			array(
				'timeout' => 10,
				'body'    => array(
					'data' => array(
						'user_email' => $value['consumer_email'],
						'user_key'   => $value['consumer_key'],
						'action'     => 'create_free_licence',
					)
				),
			)
		);

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$value['consumer_key'] = sanitize_text_field( wp_remote_retrieve_body( $response ) );
		}
	}

	// Level of configuration
	if ( ! empty( $value['auto_config_level'] ) ) {
		$value['auto_config_level'] = min( 4, max( 1, absint( $value['auto_config_level'] ) ) );
	}
	// Default
	else {
		$value['auto_config_level'] = 3;
	}

	return $value;
}


/*------------------------------------------------------------------------------------------------*/
/* CSS, JS, FAVICON ============================================================================= */
/*------------------------------------------------------------------------------------------------*/

/**
 * Add some CSS and JS to our settings pages.
 *
 * @since 1.0
 */
add_action( 'admin_enqueue_scripts', '__secupress_add_settings_scripts' );

function __secupress_add_settings_scripts( $hook_suffix ) {
	$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version = $suffix ? SECUPRESS_VERSION : time();

	// WordPress Common CSS
	wp_enqueue_style( 'secupress-wordpress-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-wordpress' . $suffix . '.css', array(), $version );

	// WordPress Common JS
	wp_enqueue_script( 'secupress-wordpress-js', SECUPRESS_ADMIN_JS_URL . 'secupress-wordpress' . $suffix . '.js', array(), $version, true );

	$pages = array(
		'toplevel_page_secupress_scanners'                 => 1,
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules'  => 1,
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_settings' => 1,
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_logs'     => 1,
	);

	if ( ! isset( $pages[ $hook_suffix ] ) ) {
		return;
	}

	// WordPress Common JS
	wp_enqueue_script( 'secupress-common-js', SECUPRESS_ADMIN_JS_URL . 'secupress-common' . $suffix . '.js', array('jquery'), $version, true );

	// SecuPress Common CSS
	wp_enqueue_style( 'secupress-common-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-common' . $suffix . '.css', array(), $version );

	// Global settings page.
	if ( SECUPRESS_PLUGIN_SLUG . '_page_secupress_settings' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-settings-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-settings' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}
	// Modules page.
	elseif ( SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-modules-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-modules' . $suffix . '.css', array( 'secupress-common-css' ), $version );
		wp_enqueue_style( 'wpmedia-css-sweetalert', SECUPRESS_ADMIN_CSS_URL . 'sweetalert' . $suffix . '.css', array(), '1.1.0' );

		// JS
		wp_enqueue_script( 'wpmedia-js-sweetalert', SECUPRESS_ADMIN_JS_URL . 'sweetalert' . $suffix . '.js', array(), '1.1.0', true );
		wp_enqueue_script( 'secupress-modules-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-modules' . $suffix . '.js', array( 'wpmedia-js-sweetalert' ), $version, true );

		wp_localize_script( 'secupress-modules-js', 'l10nmodules', array(
			'selectOneRoleMinimum' => __( 'Select 1 role minimum', 'secupress' ),

			'confirmTitle'         => __( 'Are you sure?', 'secupress' ),
			'confirmCancel'        => _x( 'No, cancel', 'verb', 'secupress' ),
			'error'                => __( 'Error', 'secupress' ),
			'unknownError'         => __( 'Unknown error.', 'secupress' ),
			'delete'               => __( 'Delete', 'secupress' ),
			'done'                 => __( 'Done!', 'secupress' ),

			'confirmDeleteBackups' => __( 'You are about to delete all your backups.', 'secupress' ),
			'yesDeleteAll'         => __( 'Yes, delete all backups', 'secupress' ),
			'deleteAllImpossible'  => __( 'Impossible to delete all backups.', 'secupress' ),
			'deletingAllText'      => __( 'Deleting all backups&hellip;', 'secupress' ),
			'deletedAllText'       => __( 'All backups deleted', 'secupress' ),

			'confirmDeleteBackup'  => __( 'You are about to delete a backup.', 'secupress' ),
			'yesDeleteOne'         => __( 'Yes, delete this backup', 'secupress' ),
			'deleteOneImpossible'  => __( 'Impossible to delete this backup.', 'secupress' ),
			'deletingOneText'      => __( 'Deleting Backup&hellip;', 'secupress' ),
			'deletedOneText'       => __( 'Backup deleted', 'secupress' ),

			'backupImpossible'     => __( 'Impossible to backup the database.', 'secupress' ),
			'backupingText'        => __( 'Backuping&hellip;', 'secupress' ),
			'backupedText'         => __( 'Backup done', 'secupress' ),

			'noBannedIPs'          => __( 'No Banned IPs anymore.', 'secupress' ),
			'IPnotFound'           => __( 'IP not found.', 'secupress' ),
			'IPremoved'            => __( 'IP removed.', 'secupress' ),
			'searchResults'        => __( 'See search result below.', 'adjective', 'secupress' ),
			'searchReset'          => _x( 'Search reset.', 'adjective', 'secupress' ),
		) );

	}
	// Scanners page.
	elseif ( 'toplevel_page_secupress_scanners' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-scanner-css',  SECUPRESS_ADMIN_CSS_URL . 'secupress-scanner' . $suffix . '.css', array( 'secupress-common-css' ), $version );
		wp_enqueue_style( 'wpmedia-css-sweetalert', SECUPRESS_ADMIN_CSS_URL . 'sweetalert' . $suffix . '.css', array(), '1.1.0' );

		// JS
		$depts = array();
		if ( is_network_admin() || ! is_multisite() ) {
			wp_enqueue_script( 'secupress-chartjs', SECUPRESS_ADMIN_JS_URL . 'chart' . $suffix . '.js', array(), '1.0.2.1', true );
			wp_enqueue_script( 'jquery-timeago',    SECUPRESS_ADMIN_JS_URL . 'jquery.timeago.js', array( 'jquery' ), '1.4.1', true );
			$depts = array( 'secupress-chartjs', 'jquery-timeago' );

			$counts = secupress_get_scanner_counts();
			wp_localize_script( 'secupress-chartjs', 'SecuPressi18nChart', array(
				'good'          => array( 'value' => $counts['good'],          'text' => __( 'Good', 'secupress' ) ),
				'warning'       => array( 'value' => $counts['warning'],       'text' => __( 'Warning', 'secupress' ) ),
				'bad'           => array( 'value' => $counts['bad'],           'text' => __( 'Bad', 'secupress' ) ),
				'notscannedyet' => array( 'value' => $counts['notscannedyet'], 'text' => __( 'Not Scanned Yet', 'secupress' ) ),
			) );

			wp_localize_script( 'jquery-timeago', 'SecuPressi18nTimeago', array(
				'prefixAgo'     => _x( '', 'timeago.prefixAgo', 'secupress' ),
				'prefixFromNow' => _x( '', 'timeago.prefixFromNow', 'secupress' ),
				'suffixAgo'     => _x( 'ago', 'timeago.suffixAgo', 'secupress' ),
				'suffixFromNow' => _x( '', 'timeago.suffixFromNow', 'secupress' ),
				'seconds'       => _x( 'a few seconds', 'timeago.seconds', 'secupress' ),
				'minute'        => _x( '1 minute', 'timeago.minute', 'secupress' ),
				'minutes'       => _x( '%d minutes', 'timeago.minutes', 'secupress' ),
				'hour'          => _x( '1 hour', 'timeago.hour', 'secupress' ),
				'hours'         => _x( '%d hours', 'timeago.hours', 'secupress' ),
				'day'           => _x( '1 day', 'timeago.day', 'secupress' ),
				'days'          => _x( '%d days', 'timeago.days', 'secupress' ),
				'month'         => _x( '1 month', 'timeago.month', 'secupress' ),
				'months'        => _x( '%d months', 'timeago.months', 'secupress' ),
				'year'          => _x( '1 year', 'timeago.year', 'secupress' ),
				'years'         => _x( '%d years', 'timeago.years', 'secupress' ),
				'wordSeparator' => _x( " ", 'timeago.wordSeparator', 'secupress' ),
			) );
		}

		wp_enqueue_script( 'secupress-scanner-js',  SECUPRESS_ADMIN_JS_URL . 'secupress-scanner' . $suffix . '.js', $depts, $version, true );
		wp_enqueue_script( 'wpmedia-js-sweetalert', SECUPRESS_ADMIN_JS_URL . 'sweetalert' . $suffix . '.js', array(), '1.1.0', true );

		wp_localize_script( 'secupress-scanner-js', 'SecuPressi18nScanner', array(
			'fixed'           => __( 'Fixed', 'secupress' ),
			'fixedPartial'    => __( 'Partially fixed', 'secupress' ),
			'notFixed'        => __( 'Not Fixed', 'secupress' ),
			'fixit'           => __( 'Fix it!', 'secupress' ),
			'error'           => __( 'Error', 'secupress' ),
			'oneManualFix'    => __( 'One fix requires your intervention.', 'secupress' ),
			'someManualFixes' => __( 'Some fixes require your intervention.', 'secupress' ),
			'spinnerUrl'      => admin_url( 'images/wpspin_light-2x.gif' ),
			'scanDetails'     => __( 'Scan Details', 'secupress' ),
			'fixDetails'      => __( 'Fix Details', 'secupress' ),
		) );
	}

	// Add the favicon.
	add_action( 'admin_head', 'secupress_favicon' );
}


/**
 * Add a site icon to each of our settings pages.
 *
 * @since 1.0
 */
function secupress_favicon() {
	$version = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '?ver=' . time() : '';
	echo '<link id="favicon" rel="shortcut icon" type="image/png" href="' . SECUPRESS_ADMIN_IMAGES_URL . 'black-shield-16.png' . $version . '" />';
}


/*------------------------------------------------------------------------------------------------*/
/* ADMIN MENU =================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Create the plugin menu and submenus.
 *
 * @since 1.0
 */
add_action( ( is_multisite() ? 'network_' : '' ) . 'admin_menu', 'secupress_create_menus' );

function secupress_create_menus() {
	global $menu;

	// Add a counter of scans with bad result.
	$count = 0;
	$scans = secupress_get_scanners();

	if ( $scans ) {
		foreach ( $scans as $scan ) {
			if ( 'bad' === $scan['status'] ) {
				++$count;
			}
		}
	}

	$count = sprintf( ' <span class="update-plugins count-%1$d"><span class="update-count">%1$d</span></span>', $count );
	$cap   = secupress_get_capability();

	// Main menu item
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, $cap, 'secupress_scanners', '__secupress_scanners', 'dashicons-shield-alt' );

	// Sub-menus
	add_submenu_page( 'secupress_scanners', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ) . $count, $cap, 'secupress_scanners', '__secupress_scanners' );
	add_submenu_page( 'secupress_scanners', __( 'Modules', 'secupress' ),  __( 'Modules', 'secupress' ),           $cap, 'secupress_modules',  '__secupress_modules' );
	add_submenu_page( 'secupress_scanners', __( 'Settings' ),              __( 'Settings' ),                       $cap, 'secupress',          '__secupress_global_settings' );
	end( $menu );
	$key = key( $menu );
	$menu[ $key ][0] .= $count;
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
	if ( ! class_exists( 'SecuPress_Settings_Global' ) ) {
		secupress_require_class( 'settings', 'global' );
	}

	SecuPress_Settings_Global::get_instance()->print_page();
}


/**
 * Add White Label in the list of settings modules.
 *
 * @since 1.0
 */
add_filter( 'secupress_global_settings_modules', '__secupress_add_white_label_settings_block' );

function __secupress_add_white_label_settings_block( $modules ) {
	if ( defined( 'WP_SWL' ) && WP_SWL ) {
		$modules[] = 'white-label';
	}
	return $modules;
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
	$times        = array_filter( (array) get_site_option( SECUPRESS_SCAN_TIMES ) );
	$reports      = array();
	$last_percent = -1;

	if ( ! empty( $times ) && is_array( $times ) ) {
		foreach ( $times as $time ) {
			$replacement = 'right';

			if ( $last_percent > -1 && $last_percent < $time['percent'] ) {
				$replacement = 'up';
			}
			else if ( $last_percent > -1 && $last_percent > $time['percent'] ) {
				$replacement = 'down';
			}

			$last_percent = $time['percent'];
			$date         = sprintf( __( '%s ago' ), human_time_diff( $time['time'] ) );

			$reports[] = sprintf(
				'<li data-percent="%1$d"><span class="dashicons mini dashicons-arrow-%2$s-alt2" aria-hidden="true"></span><strong>%3$s (%1$d %%)</strong> <span class="timeago">%4$s</span></li>',
				$time['percent'], $replacement, $time['grade'], $date
			);
		}
	}
	?>
	<div class="wrap">
		<?php secupress_admin_heading( __( 'Scanners', 'secupress' ) ); ?>

		<div class="secupress-wrapper">
			
			<div class="secupress-section-dark">
				<div class="secupress-heading secupress-flex secupress-flex-spaced secupress-wrap">
					<p class="secupress-text-medium"><?php esc_html_e( 'Welcome to SecuPress the best way to secure your website!', 'secupress' ); ?></p>
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
					<li>
						<a href="#secupress-scan" role="tab" aria-selected="true" aria-control="secupress-scan" class="secupress-current">
							<i class="icon-radar" aria-hidden="true"></i>
							<?php esc_html_e( 'Scan Security Points', 'secupress' ); ?>
						</a>
					</li>
					<li>
						<a href="#secupress-latest" role="tab" aria-selected="false" aria-control="secupress-latest">
							<i class="icon-back" aria-hidden="true"></i>
							<?php esc_html_e( 'Latest Scans', 'secupress' ); ?>
						</a>
					</li>
					<li>
						<a href="#secupress-schedule" role="tab" aria-selected="false" aria-control="secupress-schedule">
							<i class="icon-calendar" aria-hidden="true"></i>
							<?php esc_html_e( 'Schedule Scans', 'secupress' ); ?>
						</a>
					</li>
				</ul>
				
				<div id="sp-tab-scans" class="secupress-tabs-contents">
					<div id="secupress-scan" class="secupress-tab-content">
						<div class="secupress-flex secupress-row">
							<div class="secupress-flex secupress-chart">

								<div class="secupress-chart-container">
									<canvas class="secupress-chartjs" id="status_chart" width="197" height="197"></canvas>
									<div class="secupress-score">
										<span class="letter">∅</span>
									</div>
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
									<li class="status-notscannedyet" data-status="notscannedyet">
										<span class="secupress-carret"></span>
										<?php esc_html_e( 'Not scanned yet', 'secupress' ); ?>
										<span class="secupress-count-notscannedyet"></span>
									</li>
								</ul><!-- .secupress-chart-legend -->
							</div><!-- .secupress-chart.secupress-flex -->

							<div class="secupress-scan-infos">
								<p class="secupress-text-big secupress-m0">
									<?php esc_html_e( 'Congratulations', 'secupress' ); ?>
								</p>
								<p class="secupress-score secupress-m0"><?php printf( esc_html__( 'Your note is %s — %s scanned items are good.', 'secupress' ), '<span class="letter">∅</span>', '<span class="percent"></span>' ); ?></p>

								<p class="secupress-actions-line">
									<button class="secupress-button button-secupress-scan" type="button">
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
										<i><?php esc_html_e( 'Wow! My website just got an A security grade using SecuPress, what about yours?', 'secupress' ); ?></i>

										<a class="button button-small" href="https://twitter.com/intent/tweet?via=secupress&amp;url=<?php echo urlencode( esc_url_raw( 'http://secupress.fr&text=' . __( 'Wow! My website just got an A security grade using SecuPress, what about yours?', 'secupress' ) ) ); ?>">
											<span class="icon"><span class="dashicons dashicons-twitter"></span></span>
											<span class="text"><?php esc_html_e( 'Tweet that', 'secupress' ); ?></span>
										</a>
								</div>
							</div>

						</div><!-- .secupress-flex -->
					</div><!-- .secupress-tab-content -->

					<div id="secupress-latest" class="secupress-tab-content">
						<p class="secupress-text-big">
							<?php esc_html_e( 'Latest Scans', 'secupress' ) ; ?>
						</p>
						<ul class="secupress-reports-list">
						<?php if ( (bool) $reports ) { ?>
							<?php foreach ( $reports as $report ) { ?>
							<li><?php echo $report; ?></li>
							<?php } ?>
						<?php } else { ?>
							<li class="secupress-empty"><em><?php esc_html_e( 'You have no other reports for now.', 'secupress' ); ?></em></li>
						<?php } ?>
						</ul>
					</div><!-- .secupress-tab-content -->

					<div id="secupress-schedule" class="secupress-tab-content">
						<p class="secupress-text-big">
							<?php esc_html_e( 'Schedule Scans', 'secupress' ); ?>
						</p>
					</div><!-- .secupress-tab-content -->

				</div><!-- .secupress-tabs-contents -->

				<ul id="secupress-type-filters" class="secupress-big-tabs secupress-tabs secupress-flex secupress-text-start hide-if-no-js" role="tabpanel">
				<?php
					$tabs = array(
						'notscannedyet'	=> esc_html__( 'New', 'secupress' ),
						'bad'			=> esc_html__( 'Bad', 'secupress' ),
						'warning'		=> esc_html__( 'Warning', 'secupress' ),
						'good'			=> esc_html__( 'Good', 'secupress' ),
					);
					$current = 'bad';
					foreach ( $tabs as $slug => $name ) {
				?>
					<li class="secupress-big-tab-<?php echo $slug; ?>">
						<a href="#tab-<?php echo $slug; ?>" aria-control="tab-<?php echo $slug; ?>" role="tab"<?php echo ( $slug === $current ? ' class="secupress-current"' : '' ); ?> data-type="<?php echo $slug; ?>">
							<span class="secupress-tab-title"><?php echo $name; ?></span>
							<span class="secupress-tab-subtitle">
								<?php printf( esc_html__( '%s issues', 'secupress' ), '<span class="secupress-count-' . $slug . ' secupress-count"></span>' );  ?>
							</span>
						</a>
					</li>
				<?php
					}
				?>
				</ul>

			</div><!-- .secupress-section-dark -->

			<div class="secupress-section-gray secupress-bordered-lat">
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
			<div class="secupress-section-light secupress-bordered-lat secupress-lined-b secupress-pt1p">
				<?php secupress_main_scan(); ?>
			</div>

			<?php
				wp_nonce_field( 'secupress_score', 'secupress_score', false );
			?>
		</div>

	</div>
	<?php
}


/*------------------------------------------------------------------------------------------------*/
/* TOOLS ======================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Print the settings page title.
 *
 * @since 1.0
 */
function secupress_admin_heading( $title = '' ) {
	$heading_tag = secupress_wp_version_is( '4.3-alpha' ) ? 'h1' : 'h2';
	printf( '<%1$s class="secupress-page-title screen-reader-text">%2$s <sup>%3$s</sup> %4$s</%1$s>', $heading_tag, SECUPRESS_PLUGIN_NAME, SECUPRESS_VERSION, $title );
}


function secupress_main_scan() {
	secupress_require_class( 'scan' );

	$secupress_tests = secupress_get_tests();
	$scanners        = secupress_get_scanners();
	$fixes           = secupress_get_scanner_fixes();
	$heading_tag     = secupress_wp_version_is( '4.4-alpha' ) ? 'h2' : 'h3';
	// Actions the user needs to perform for a fix.
	$fix_actions     = SecuPress_Scan::get_and_delete_fix_actions();
	// Auto-scans: scans that will be executed on page load.
	$autoscans       = SecuPress_Scan::get_and_delete_autoscans();

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
	?>
	<div id="secupress-tests">
		<?php
		foreach ( $secupress_tests as $prio_key => $class_name_parts ) {
			$i         = 0;
			$prio_data = SecuPress_Scan::get_priorities( $prio_key );
			?>
			<div class="secupress-table-prio-all secupress-table-prio-<?php echo $prio_key; ?>">

				<div class="secupress-prio-title prio-<?php echo $prio_key; ?>">
					<?php echo '<' . $heading_tag . ' class="secupress-prio-h" title="' . $prio_data['description'] . '">' . $prio_data['title'] . '</' . $heading_tag . '>'; ?>
				</div>
				
				<?php
				// For this priority, order the scans by status: 'bad', 'warning', 'notscannedyet', 'good'.
				$ordered_scan_names = array();

				foreach ( $class_name_parts as $class_name_part ) {
					if ( ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
						continue;
					}

					secupress_require_class( 'scan', $class_name_part );

					$option_name = strtolower( $class_name_part );
					$ordered_scan_names[ $option_name ] = $class_name_part;
				}

				$class_name_parts = $ordered_scan_names;

				$this_prio_bad_scans     = array_intersect_key( $class_name_parts, $bad_scans );
				$this_prio_warning_scans = array_intersect_key( $class_name_parts, $warning_scans );
				$this_prio_good_scans    = array_intersect_key( $class_name_parts, $good_scans );
				$class_name_parts        = array_diff_key( $class_name_parts, $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );
				$class_name_parts        = array_merge( $this_prio_bad_scans, $this_prio_warning_scans, $class_name_parts, $this_prio_good_scans );
				unset( $ordered_scan_names, $this_prio_bad_scans, $this_prio_warning_scans, $this_prio_good_scans );

				// Allowed tags in "Learn more" contents.
				$allowed_tags = array(
					'a'      => array( 'href' => array(),'title' => array(), 'target' => array(), ),
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

				// Print the rows.
				foreach ( $class_name_parts as $option_name => $class_name_part ) {
					++$i;

					$class_name   = 'SecuPress_Scan_' . $class_name_part;
					$current_test = $class_name::get_instance();
					$css_class    = ' type-' . sanitize_key( $class_name::$type );
					$css_class   .= $i % 2 === 0 ? ' alternate-2' : ' alternate-1';
					$fix_message  = '';

					// Scan
					$status_text  = ! empty( $scanners[ $option_name ]['status'] ) ? secupress_status( $scanners[ $option_name ]['status'] )    : secupress_status( 'notscannedyet' );
					$status_class = ! empty( $scanners[ $option_name ]['status'] ) ? sanitize_html_class( $scanners[ $option_name ]['status'] ) : 'notscannedyet';
					$css_class   .= ' status-' . $status_class;
					$css_class   .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';
					$css_class   .= false === $current_test::$fixable || 'pro' === $current_test::$fixable && ! secupress_is_pro() ? ' not-fixable' : '';

					if ( ! empty( $scanners[ $option_name ]['msgs'] ) ) {
						$scan_message = secupress_format_message( $scanners[ $option_name ]['msgs'], $class_name_part );
					} else {
						$scan_message = '&#175;';
					}

					// Fix
					$fix_status_text  = ! empty( $fixes[ $option_name ]['status'] ) && $fixes[ $option_name ]['status'] !== 'good' ? secupress_status( $fixes[ $option_name ]['status'] ) : '';
					$fix_css_class    = ! empty( $fixes[ $option_name ]['status'] ) ? ' status-' . sanitize_html_class( $fixes[ $option_name ]['status'] ) : ' status-cantfix';

					if ( ! empty( $fixes[ $option_name ]['msgs'] ) && $status_class !== 'good' ) {
						$fix_message = secupress_format_message( $fixes[ $option_name ]['msgs'], $class_name_part );
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
								if ( true === $current_test::$fixable ) {
									?>
									<a class="secupress-button-primary secupress-button-mini secupress-fixit<?php echo $current_test::$delayed_fix ? ' delayed-fix' : '' ?>" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part ), 'secupress_fixit_' . $class_name_part ); ?>">
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
													<?php _e( 'How does it work?', 'secupress' ); ?>
											</button>
										</span>
									</div>
									<?php
								} elseif ( 'pro' === $current_test::$fixable && ! secupress_is_pro() ) { /* //// $needs-pro */
									?>
									<button type="button" class="secupress-button-primary secupress-button-mini secupress-go-pro">
										<?php esc_html_e( 'Fix it with Pro', 'secupress' ); ?>
										<i class="icon-secupress-simple" aria-hidden="true"></i>
									</button>
									<?php
								} else { // Really not fixable by the plugin
									printf( '<em>(%s)</em>', esc_html__( 'Cannot be fixed automatically.', 'secupress' ) );
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
									<a class="secupress-button secupress-button-mini secupress-scanit" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part ), 'secupress_scanner_' . $class_name_part ); ?>">
										<span class="icon">
											<i class="icon-refresh" aria-hidden="true"></i>
										</span>
										<span class="text">
											<?php _ex( 'Re-Scan', 'scan a test', 'secupress' ); ?>
										</span>
									</a>
								</p>
							</div>
						</div>
						
						<?php if ( ! empty( $fix_message ) ) { ?>
						<div class="secupress-flex secupress-flex-spaced secupress-fix-result secupress-bg-gray">
							<div class="secupress-fix-result-message">
								<?php echo $fix_message; ?>
							</div>
							<div class="secupress-fix-result-retryfix">
								<a href="#" class="secupress-button secupress-button-primary secupress-button-mini">
									<span class="icon">
										<i class="icon-shield"></i>
									</span>
									<span class="text">
										<?php esc_html_e( 'Retry to fix', 'secupress' ); ?>
									</span>
								</a>
							</div>
						</div>
						<?php } ?>
						<?php // TODO: Make it appears dynamically ?>
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
									<a href="#" class="secupress-button secupress-button-mini secupress-ask-support">
										<span class="icon">
											<i class="icon-ask"></i>
										</span>
										<span class="text">
											<?php esc_html_e( 'Ask support about it', 'secupress' ); ?>
										</span>
									</a>
								</p>
						</div>
						
						<?php // hidden items used for Sweet Alerts  ?>
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
								<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
									<h3><?php echo _n( 'This action requires your attention', 'These actions require your attention', count( $fix_actions ), 'secupress' ); ?></h3>
									<?php
									echo implode( '', $fix_actions );
									submit_button( __( 'Fix it!', 'secupress' ) );
									$current_test->get_fix_action_fields( array_keys( $fix_actions ) );
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

		if ( WP_DEBUG && function_exists( 'pre_print_r' ) ) {////
			echo '<code>$scanners</code>:';
			pre_print_r($scanners,1);
			echo '<code>$fixes</code>:';
			pre_print_r($fixes,1);
			if ( is_multisite() ) {
				echo '<code>$sub_sites</code>:';
				pre_print_r(secupress_get_results_for_ms_scanner_fixes(),1);
				echo '<code>$active_plugins</code>:';
				pre_print_r(get_site_option( 'secupress_active_plugins' ),1);
				echo '<code>$active_themes</code>:';
				pre_print_r(get_site_option( 'secupress_active_themes' ),1);
				echo '<code>$default_roles</code>:';
				pre_print_r(get_site_option( 'secupress_default_role' ),1);
			}
		}
		?>
	</div>
	<?php
}


function secupress_status( $status ) {
	$template = '<span class="dashicons dashicons-shield-alt secupress-dashicon" aria-hidden="true"></span> %s';

	switch ( $status ):
		case 'bad':
			return wp_sprintf( $template, __( 'Bad', 'secupress' ) );
		case 'good':
			return wp_sprintf( $template, __( 'Good', 'secupress' ) );
		case 'warning':
			return wp_sprintf( $template, __( 'Warning', 'secupress' ) );
		case 'cantfix':
			return '&#160;';
		default:
			return wp_sprintf( $template, __( 'Not scanned yet', 'secupress' ) );
	endswitch;
}


function secupress_sidebox( $args ) {
	$defaults = array(
		'id'      => '',
		'title'   => 'Missing',
		'content' => 'Missing',
		'context' => 'side', // side or top
	);
	$args    = wp_parse_args( $args, $defaults );
	$return  = '<div class="secupress-postbox postbox" id="' . $args['id'] . '">';
	$return .= '<h3 class="hndle"><span><b>' . $args['title'] . '</b></span></h3>';
	$return .= '<div class="inside">' . $args['content'] . '</div></div>';

	echo $return;
}
