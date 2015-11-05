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
	register_setting( 'secupress_global_settings', SECUPRESS_SETTINGS_SLUG, '__secupress_global_settings_callback' );
}


/**
 * Sanitize our global settings.
 *
 * @since 1.0
 */
function __secupress_global_settings_callback( $value ) {
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
	$pages = array(
		'toplevel_page_secupress',
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_settings',
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules',
		SECUPRESS_PLUGIN_SLUG . '_page_secupress_scanners',
	);

	if ( ! in_array( $hook_suffix, $pages ) ) {
		return;
	}

	$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
	$version = $suffix ? SECUPRESS_VERSION : time();

	// Common CSS
	wp_enqueue_style( 'secupress-common-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-common' . $suffix . '.css', array(), $version );

	// Global settings page.
	if ( SECUPRESS_PLUGIN_SLUG . '_page_secupress_settings' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-settings-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-settings' . $suffix . '.css', array( 'secupress-common-css' ), $version );
	}

	// Modules page.
	elseif ( SECUPRESS_PLUGIN_SLUG . '_page_secupress_modules' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-modules-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-modules' . $suffix . '.css', array( 'secupress-common-css' ), $version );

		// JS
		wp_enqueue_script( 'secupress-zxcvbn-async', includes_url( '/js/zxcvbn.min.js' ), array( 'jquery' ) );
		wp_enqueue_script( 'secupress-modules-js', SECUPRESS_ADMIN_JS_URL . 'secupress-modules' . $suffix . '.js', array( 'secupress-zxcvbn-async', 'password-strength-meter' ), $version, true );

		wp_localize_script( 'secupress-modules-js', 'l10nmodules', array(
			'selectOneRoleMinimum' => __( 'Select 1 role minimum', 'secupress' ),
		) );
	}

	// Scanners page.
	elseif ( SECUPRESS_PLUGIN_SLUG . '_page_secupress_scanners' === $hook_suffix ) {
		// CSS
		wp_enqueue_style( 'secupress-scanner-css', SECUPRESS_ADMIN_CSS_URL . 'secupress-scanner' . $suffix . '.css', array( 'secupress-common-css' ), $version );
		wp_enqueue_style( 'wpmedia-css-sweetalert', SECUPRESS_ADMIN_CSS_URL . 'sweetalert' . $suffix . '.css', array(), '1.1.0' );

		// JS
		wp_enqueue_script( 'secupress-chartjs',    SECUPRESS_ADMIN_JS_URL . 'chart' . $suffix . '.js', array(), '1.0.2.1', true );
		wp_enqueue_script( 'jquery-timeago',       SECUPRESS_ADMIN_JS_URL . 'jquery.timeago.js', array( 'jquery' ), '1.4.1', true );
		wp_enqueue_script( 'secupress-scanner-js', SECUPRESS_ADMIN_JS_URL . 'secupress-scanner' . $suffix . '.js', array( 'secupress-chartjs', 'jquery-timeago' ), $version, true );
		wp_enqueue_script( 'wpmedia-js-sweetalert', SECUPRESS_ADMIN_JS_URL . 'sweetalert' . $suffix . '.js', array(), '1.1.0', true );

		$counts = secupress_get_scanner_counts();
		wp_localize_script( 'secupress-chartjs', 'SecuPressi18nChart', array(
			'good'          => array( 'value' => $counts['good'],          'text' => __( 'Good', 'secupress' ) ),
			'warning'       => array( 'value' => $counts['warning'],       'text' => __( 'Warning', 'secupress' ) ),
			'bad'           => array( 'value' => $counts['bad'],           'text' => __( 'Bad', 'secupress' ) ),
			'notscannedyet' => array( 'value' => $counts['notscannedyet'], 'text' => __( 'Not Scanned Yet', 'secupress' ) ),
		) );

		wp_localize_script( 'secupress-scanner-js', 'SecuPressi18nScanner', array(
			'fixed'           => __( 'Fixed', 'secupress' ),
			'fixedPartial'    => __( 'Partially fixed', 'secupress' ),
			'notFixed'        => __( 'Not Fixed', 'secupress' ),
			'fixit'           => __( 'Fix it!', 'secupress' ),
			'error'           => __( 'Error', 'secupress' ),
			'oneManualFix'    => __( 'One fix requires your intervention.', 'secupress' ),
			'someManualFixes' => __( 'Some fixes require your intervention.', 'secupress' ),
			'spinnerUrl'      => admin_url( 'images/wpspin_light-2x.gif' ),
		) );
	}

	// Add the favicon, no need to test again the page we're in.
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
add_action( 'admin_menu', 'secupress_create_menus' );

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

	// Main menu item
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, 'administrator', 'secupress', '__secupress_dashboard', 'dashicons-shield-alt' );

	// Sub-menus
	add_submenu_page( 'secupress', __( 'Dashboard' ),             __( 'Dashboard' ),                      'administrator', 'secupress',          '__secupress_dashboard' );
	add_submenu_page( 'secupress', __( 'Settings' ),              __( 'Settings' ),                       'administrator', 'secupress_settings', '__secupress_global_settings' );
	add_submenu_page( 'secupress', __( 'Modules', 'secupress' ),  __( 'Modules', 'secupress' ),           'administrator', 'secupress_modules',  '__secupress_modules' );
	add_submenu_page( 'secupress', __( 'Scanners', 'secupress' ), __( 'Scanners', 'secupress' ) . $count, 'administrator', 'secupress_scanners', '__secupress_scanners' );

	// Add the counter to the main menu: it can't be added with `add_menu_page()` because it would change the value of the screen ID (yes, it's utterly stupid).
	end( $menu );
	$key = key( $menu );
	$menu[ $key ][0] .= $count;
}


/*------------------------------------------------------------------------------------------------*/
/* SETTINGS PAGES =============================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Dashboard page.
 *
 * @since 1.0
 */
function __secupress_dashboard() {
	?>
	<div class="wrap">
		<?php secupress_admin_heading( __( 'Dashboard' ) ); ?>

		<div class="secupress-wrapper">
			<?php
			delete_option( SECUPRESS_SCAN_SLUG );
			delete_option( SECUPRESS_SCAN_TIMES );
			delete_option( SECUPRESS_FIX_SLUG );
			?>
		</div>
	</div>
	<?php
}


/**
 * Global settings page.
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
	$times        = array_filter( (array) get_option( SECUPRESS_SCAN_TIMES ) );
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

	$boxes = array(
		'score' => array(
			__( 'Your Score', 'secupress' ),
			'<canvas id="status_chart" width="300" height="300"></canvas>' .
			'<div class="score_info2">' .
				'<span class="letter">&ndash;</span>' .
				'<span class="percent">(0 %)</span>' .
				'<div class="score_results">' . sprintf( __( '%s:', 'secupress' ), '<strong>' . __( 'Latest Reports', 'secupress' ) . '</strong>' ) . '<br>' .
					'<ul>' .
						implode( "\n", array_reverse( $reports ) ) .
					'</ul>' .
				'</div>' .
			'</div>' .
			'<div class="legend">' .
				'<span class="status-good"><span class="secupress-dashicon dashicons dashicons-shield-alt" aria-hidden="true"></span> ' . __( 'Good', 'secupress' ) . '</span> | ' .
				'<span class="status-bad"><span class="secupress-dashicon dashicons dashicons-shield-alt" aria-hidden="true"></span> ' . __( 'Bad', 'secupress' ) . '</span> | ' .
				'<span class="status-warning"><span class="secupress-dashicon dashicons dashicons-shield-alt" aria-hidden="true"></span> ' . __( 'Warning', 'secupress' ) . '</span> | ' .
				'<span class="status-notscannedyet"><span class="secupress-dashicon dashicons dashicons-shield-alt" aria-hidden="true"></span> ' . __( 'Not scanned yet', 'secupress' ) . '</span>' .
			'</div>' .
			'<div id="tweeterA" class="hidden">' .
				'<hr>' .
				'<span class="dashicons dashicons-twitter"></span> ' .
				'<i>' . __( 'Wow! My website just got an A security grade using SecuPress, what about yours?', 'secupress' ) . '</i> ' .
				'<a class="button button-small" href="https://twitter.com/intent/tweet?via=secupress&amp;url=' . urlencode( 'http://secupress.fr&text=' . __( 'Wow! My website just got an A security grade using SecuPress, what about yours?', 'secupress' ) ) . '">Tweet &raquo;</a>' .
			'</div>'
		),
	//	'premium' => array(
	//		'SecuPress Security Pro',
	//		__( '<img src="https://dl-web.dropbox.com/get/BAW/V3/secupress_sign.png?_subject_uid=45956904&w=AABRKI608fHD9wxoU4qXaJ3TlsmpqTO_vpZT969iKmlrbw"><br>Get "<b>SecuPress Security Pro</b>" now and fix all to get a Securer installation!<br><a href="#">Clic here</a>', 'secupress' )
	//	),
	//	'infos' => array(
	//		__( 'Informations', 'secupress' ),
	//	),
	);
	?>
	<div class="wrap">
		<?php
		secupress_admin_heading( __( 'Scanners', 'secupress' ) ); ?>

		<div class="secupress-wrapper">
			<?php
			foreach ( $boxes as $id => $box ) {
				secupress_sidebox( array( 'id' => $id, 'title' => $box[0], 'content' => $box[1], 'context' => 'top' ) );
			}

			secupress_main_scan();

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
	$heading_tag = secupress_wp_version_is( '4.3.0-alpha' ) ? 'h1' : 'h2';
	printf( '<%1$s>%2$s <sup>%3$s</sup> %4$s</%1$s>', $heading_tag, SECUPRESS_PLUGIN_NAME, SECUPRESS_VERSION, $title );
}


function secupress_main_scan() {
	secupress_require_class( 'scan' );

	$secupress_tests = secupress_get_tests();
	$scanners        = secupress_get_scanners();
	$fixes           = secupress_get_scanner_fixes();
	// Actions the user needs to perform for a fix.
	$fix_actions     = SecuPress_Scan::get_and_delete_fix_actions();
	// Auto-scans: scans that will be executed on page load.
	$autoscans       = SecuPress_Scan::get_and_delete_autoscans();

	// Store the scans in 2 variables. They will be used to order the scans by status: 'bad', 'warning', 'notscannedyet', 'good'.
	$before_not_scanned = array( 'bad' => array(), 'warning' => array(), );
	$after_not_scanned  = array( 'good' => array(), );

	if ( ! empty( $scanners ) ) {
		foreach ( $scanners as $class_name_part => $details ) {
			if ( isset( $before_not_scanned[ $details['status'] ] ) ) {
				$before_not_scanned[ $details['status'] ][ $class_name_part ] = $details['status'];
			}
			elseif ( isset( $after_not_scanned[ $details['status'] ] ) ) {
				$after_not_scanned[ $details['status'] ][ $class_name_part ] = $details['status'];
			}
		}
	}

	$before_not_scanned = array_merge( $before_not_scanned['bad'], $before_not_scanned['warning'] );
	$after_not_scanned  = $after_not_scanned['good'];
	?>
	<a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=all' ), 'secupress_scanner_all' ); ?>" class="button button-primary button-large button-secupress-scan">
		<?php _e( 'One Click Scan', 'secupress' ); ?>
	</a>

	<div class="square-filter priorities hide-if-no-js">
		<button type="button" class="active" data-type="all"><?php _ex( 'All Priorities', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="high"><?php _ex( 'High Priority', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="medium"><?php _ex( 'Medium Priority', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="low"><?php _ex( 'Low Priority', 'priority', 'secupress' ); ?></button>
	</div>

	<div class="square-filter statuses hide-if-no-js">
		<button type="button" class="active" data-type="all"><?php _ex( 'All Statuses', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="good"><?php _ex( 'Good Status', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="warning"><?php _ex( 'Warning Status', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="bad"><?php _ex( 'Bad Status', 'priority', 'secupress' ); ?></button><?php
		?><button type="button" data-type="notscannedyet"><?php _ex( 'Not Scanned Yet', 'priority', 'secupress' ); ?></button>
	</div>

	<div id="secupress-tests">
		<?php
		foreach ( $secupress_tests as $prio_key => $class_name_parts ) {
			$i         = 0;
			$prio_data = SecuPress_Scan::get_priorities( $prio_key );
			?>
			<div class="table-prio-all table-prio-<?php echo $prio_key; ?>">

				<div class="prio-<?php echo $prio_key; ?>">
					<h2><?php echo $prio_data['title']; ?></h2>
					<?php echo $prio_data['description']; ?>
				</div>

				<div class="tablenav top hide-if-no-js">
					<div class="alignleft actions bulkactions">
						<label for="bulk-action-<?php echo $prio_key; ?>" class="screen-reader-text"><?php _e( 'Select bulk action' ); ?></label>
						<select name="action" id="bulk-action-<?php echo $prio_key; ?>">
							<option value="-1" selected="selected"><?php _e( 'Bulk Actions' ); ?></option>
							<option value="scanit"><?php _e( 'Scan it', 'secupress' ); ?></option>
							<option value="fixit"><?php _e( 'Fix it', 'secupress' ); ?></option>
						</select>
						<input type="button" id="doaction-<?php echo $prio_key; ?>" class="button action" value="<?php _e( 'Apply' ); ?>">
					</div>
				</div>


				<table class="wp-list-table widefat">
					<thead>
						<tr>
							<td class="manage-column column-cb secupress-check-column hide-if-no-js">
								<label for="cb-select-all-<?php echo $prio_key; ?>-1" class="screen-reader-text"><?php _e( 'Select All' ); ?></label>
								<input id="cb-select-all-<?php echo $prio_key; ?>-1" type="checkbox"/>
							</td>
							<th scope="col" class="secupress-desc"><?php _e( 'Description', 'secupress' ); ?></th>
							<th scope="col" class="secupress-scan-status" data-sort="string"><?php _e( 'Scan Status', 'secupress' ); ?></th>
							<th scope="col" class=".secupress-scan-result"><?php _e( 'Scan Result', 'secupress' ); ?></th>
							<th scope="col" class="secupress-fix-status"><?php _e( 'Fix Status', 'secupress' ); ?></th>
							<th scope="col" class="secupress-fix-result"><?php _e( 'Fix Result', 'secupress' ); ?></th>
						</tr>
					</thead>

					<tfoot>
						<tr>
							<td class="manage-column column-cb secupress-check-column hide-if-no-js">
								<label for="cb-select-all-<?php echo $prio_key; ?>-2" class="screen-reader-text"><?php _e( 'Select All' ); ?></label>
								<input id="cb-select-all-<?php echo $prio_key; ?>-2" type="checkbox"/>
							</td>
							<th scope="col" class="secupress-desc"><?php _e( 'Description', 'secupress' ); ?></th>
							<th scope="col" class="secupress-scan-status"><?php _e( 'Scan Status', 'secupress' ); ?></th>
							<th scope="col" class=".secupress-scan-result"><?php _e( 'Scan Result', 'secupress' ); ?></th>
							<th scope="col" class="secupress-fix-status"><?php _e( 'Fix Status', 'secupress' ); ?></th>
							<th scope="col" class="secupress-fix-result"><?php _e( 'Fix Result', 'secupress' ); ?></th>
						</tr>
					</tfoot>

					<tbody>
					<?php
					// For this priority, order the scans by result status.
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

					$this_prio_before_not_scanned = array_intersect_key( $class_name_parts, $before_not_scanned );
					$this_prio_after_not_scanned  = array_intersect_key( $class_name_parts, $after_not_scanned );
					$class_name_parts = array_diff_key( $class_name_parts, $this_prio_after_not_scanned );
					$class_name_parts = array_merge( $this_prio_before_not_scanned, $class_name_parts, $this_prio_after_not_scanned );
					unset( $ordered_scan_names, $this_prio_before_not_scanned, $this_prio_after_not_scanned );

					// Print the rows.
					foreach ( $class_name_parts as $option_name => $class_name_part ) {
						++$i;

						$class_name   = 'SecuPress_Scan_' . $class_name_part;
						$current_test = $class_name::get_instance();
						$css_class    = ' type-' . sanitize_key( $class_name::$type );
						$css_class   .= $i % 2 === 0 ? ' alternate-2' : ' alternate-1';

						// Scan
						$status_text  = ! empty( $scanners[ $option_name ]['status'] ) ? secupress_status( $scanners[ $option_name ]['status'] )    : secupress_status( 'notscannedyet' );
						$status_class = ! empty( $scanners[ $option_name ]['status'] ) ? sanitize_html_class( $scanners[ $option_name ]['status'] ) : 'notscannedyet';
						$css_class   .= ' status-' . $status_class;
						$css_class   .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';

						if ( ! empty( $scanners[ $option_name ]['msgs'] ) ) {
							$scan_message = secupress_format_message( $scanners[ $option_name ]['msgs'], $class_name_part );
						} else {
							$scan_message = '&#175;';
						}

						// Fix
						$fix_status_text  = ! empty( $fixes[ $option_name ]['status'] ) && $fixes[ $option_name ]['status'] !== 'good' ? secupress_status( $fixes[ $option_name ]['status'] ) : '&#160;';
						$fix_css_class    = ! empty( $fixes[ $option_name ]['status'] ) ? ' status-' . sanitize_html_class( $fixes[ $option_name ]['status'] ) : ' status-cantfix';

						if ( ! empty( $fixes[ $option_name ]['msgs'] ) && $status_class !== 'good' ) {
							$fix_message = secupress_format_message( $fixes[ $option_name ]['msgs'], $class_name_part );
						} else {
							$fix_message = '';
						}
						?>
						<tr class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all<?php echo $css_class; ?>">
							<th scope="row" class="secupress-check-column hide-if-no-js">
								<label class="screen-reader-text" for="cb-select-<?php echo $class_name_part; ?>"><?php _e( 'Select this scan', 'secupress' ); ?></label>
								<input id="cb-select-<?php echo $class_name_part; ?>" type="checkbox" class="secupress-checkbox-<?php echo $prio_key; ?>" />
							</th>
							<td>
								<?php echo $class_name::$title; ?>
								<div class="secupress-row-actions">
									<span class="hide-if-no-js">
										<button type="button" class="secupress-details link-like" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get details', 'secupress' ); ?>"><?php _e( 'Learn more', 'secupress' ); ?></button>
									</span>
								</div>
							</td>
							<td class="secupress-scan-status">
								<div class="secupress-status"><?php echo $status_text; ?></div>

								<div class="secupress-row-actions">
									<a class="button button-secondary button-small secupress-scanit" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_scanner&test=' . $class_name_part ), 'secupress_scanner_' . $class_name_part ); ?>"><?php _ex( 'Scan', 'scan a test', 'secupress' ); ?></a>
								</div>
							</td>
							<td class="secupress-scan-result">
								<?php echo $scan_message; ?>
							</td>
							<td class="secupress-fix-status<?php echo $fix_css_class; ?>">
								<div class="secupress-status"><?php echo $fix_status_text; ?></div>

								<div class="secupress-row-actions">
									<?php
									if ( $current_test::$fixable ) { ?>
										<a class="button button-secondary button-small secupress-fixit" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=secupress_fixit&test=' . $class_name_part ), 'secupress_fixit_' . $class_name_part ); ?>"><?php _e( 'Fix it!', 'secupress' ); ?></a>
										<?php
									} else { ?>
										<button type="button" class="button button-secondary button-small secupress-go-premium"><?php _e( 'Premium Upgrade', 'secupress' ); ?></button>
										<?php
									}
									?>
								</div>
							</td>
							<td class="secupress-fix-result">
								<?php echo $fix_message; ?>
							</td>
						</tr>
						<?php
						if ( $class_name_part === $fix_actions[0] ) {
							$fix_actions = explode( ',', $fix_actions[1] );
							$fix_actions = array_combine( $fix_actions, $fix_actions );
							$fix_actions = $current_test->get_required_fix_action_template_parts( $fix_actions );

							if ( $fix_actions ) { ?>
								<tr class="test-fix-action">
									<td colspan="6">
										<form method="post" action="<?php echo admin_url( 'admin-post.php' ); ?>">
											<h3><?php echo _n( 'This action requires your attention', 'These actions require your attention', count( $fix_actions ), 'secupress' ); ?></h3>
											<?php
											echo implode( '', $fix_actions );
											submit_button( __( 'Fix it!', 'secupress' ) );
											$current_test->get_fix_action_fields( $fix_actions );
											?>
										</form>
									</td>
								</tr>
								<?php
							}

							$fix_actions = array( 0 => false );
						}
						?>
						<tr id="details-<?php echo $class_name_part; ?>" class="details hide-if-js">
							<td colspan="6">
								<?php echo wp_kses_post( $current_test::$more ); ?>
							</td>
						</tr>
						<?php
					}
					?>
					</tbody>
				</table>

			</div>
			<?php
		} // foreach prio

		if ( function_exists( 'pre_print_r' ) ) {////
			echo '<code>$scanners</code>:';
			pre_print_r($scanners,1);
			echo '<code>$fixes</code>:';
			pre_print_r($fixes,1);
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

