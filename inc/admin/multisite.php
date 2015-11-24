<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/*------------------------------------------------------------------------------------------------*/
/* !MULTISITE SETTINGS API ====================================================================== */
/*------------------------------------------------------------------------------------------------*/

add_filter( 'secupress_whitelist_site_options', 'secupress_site_option_update_filter' );

/**
 * {@internal Missing Short Description}}
 *
 * @since 1.0
 *
 * @param (array) $options
 * @return (array)
 */
function secupress_site_option_update_filter( $options ) {
	$whitelist = secupress_cache_data( 'new_whitelist_site_options' );

	if ( is_array( $whitelist ) ) {
		$options = add_option_whitelist( $whitelist, $options );
	}

	return $options;
}


/*------------------------------------------------------------------------------------------------*/
/* !SAVE SETTINGS ON FORM SUBMIT ================================================================ */
/*------------------------------------------------------------------------------------------------*/

// !options.php do not handle site options. Let's use admin-post.php for multisite installations.

add_action( 'admin_post_update', 'secupress_update_site_option_on_submit' );

function secupress_update_site_option_on_submit() {
	$option_groups = array( 'secupress_global_settings' => 1 );
	$modules       = secupress_get_modules();

	foreach ( $modules as $module => $atts ) {
		$option_groups["secupress_{$module}_settings"] = 1;
	}

	if ( ! isset( $_POST['option_page'], $option_groups[ $_POST['option_page'] ] ) ) {
		return;
	}

	$option_group = $_POST['option_page'];

	if ( ! current_user_can( secupress_get_capability() ) ) {
		wp_die( __( 'Cheatin&#8217; uh?' ), 403 );
	}

	check_admin_referer( $option_group . '-options' );

	$whitelist_options = apply_filters( 'secupress_whitelist_site_options', array() );

	if ( ! isset( $whitelist_options[ $option_group ] ) ) {
		wp_die( __( '<strong>ERROR</strong>: options page not found.' ) );
	}

	$options = $whitelist_options[ $option_group ];

	if ( $options ) {

		foreach ( $options as $option ) {
			$option = trim( $option );
			$value  = null;

			if ( isset( $_POST[ $option ] ) ) {
				$value = $_POST[ $option ];
				if ( ! is_array( $value ) ) {
					$value = trim( $value );
				}
				$value = wp_unslash( $value );
			}

			update_site_option( $option, $value );
		}

	}

	/**
	 * Handle settings errors and return to options page
	 */
	// If no settings errors were registered add a general 'updated' message.
	if ( ! count( get_settings_errors() ) ) {
		add_settings_error( 'general', 'settings_updated', __( 'Settings saved.' ), 'updated' );
	}
	set_transient( 'settings_errors', get_settings_errors(), 30 );

	/**
	 * Redirect back to the settings page that was submitted
	 */
	$goback = add_query_arg( 'settings-updated', 'true',  wp_get_referer() );
	wp_redirect( $goback );
	exit;
}


/*------------------------------------------------------------------------------------------------*/
/* ADMIN MENU + NOTICE ========================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Create the plugin menu item in sites.
 * Also display an admin notice.
 *
 * @since 1.0
 */
add_action( 'admin_menu', 'secupress_create_subsite_menu' );

function secupress_create_subsite_menu() {
	global $pagenow;

	if ( is_network_admin() || is_user_admin() || ! current_user_can( secupress_get_capability( true ) ) ) {
		return;
	}

	$site_id = get_current_blog_id();
	$sites   = secupress_get_results_for_ms_scanner_fixes();
	$cap     = secupress_get_capability( true );
	$menu    = false;

	if ( ! $sites ) {
		return;
	}

	foreach ( $sites as $site_data ) {
		if ( isset( $site_data[ $site_id ] ) ) {
			$menu = true;
			break;
		}
	}

	if ( ! $menu ) {
		return;
	}

	// Menu item
	add_menu_page( SECUPRESS_PLUGIN_NAME, SECUPRESS_PLUGIN_NAME, $cap, 'secupress_scanners', '__secupress_subsite_scanners', 'dashicons-shield-alt' );

	// Display a notice for Administrators.
	if ( 'admin.php' !== $pagenow || empty( $_GET['page'] ) || 'secupress_scanners' !== $_GET['page'] ) {
		/* translators: 1 is an URL, 2 is the plugin name */
		$message = sprintf( __( 'Some security issues must be fixed, please visit <a href="%1$s">%2$s\'s page</a>.', 'secupress' ), admin_url( 'admin.php?page=secupress_scanners' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' );
		secupress_add_notice( $message, null, 'subsite-security-issues' );
	} else {
		// The user is on the plugin page: make sure to not display the notice.
		secupress_dismiss_notice( 'subsite-security-issues' );
	}
}


/**
 * Our "security issues" notice must be shown to the site's Administrators: change the capability for the ajax callback.
 *
 * @since 1.0
 *
 * @param (string) Capability or user role.
 * @param (string) The notice Identifier.
 *
 * @return (string) Capability or user role.
 */
add_filter( 'secupress_ajax_dismiss_notice_capability', 'secupress_ajax_dismiss_multisite_notice_capability', 10, 2 );

function secupress_ajax_dismiss_multisite_notice_capability( $capacity, $notice_id ) {
	return 'subsite-security-issues' === $notice_id ? secupress_get_capability( true ) : $capacity;
}


/**
 * When all the site's fixes are done, remove the "dismissed notice" value from the users meta.
 * That way, the notice can be shown again later if needed (more fixes to do).
 *
 * @since 1.0
 */
add_action( 'secupress_empty_results_for_ms_scanner_fixes', 'secupress_remove_subsite_security_issues_notice_meta' );

function secupress_remove_subsite_security_issues_notice_meta() {
	global $wpdb;
	// Get all Administrators that have dismissed our notice.
	$users = get_users( array(
		'role'         => secupress_get_capability( true ),
		'meta_key'     => $wpdb->get_blog_prefix() . SecuPress_Admin_Notices::META_NAME,
		'meta_value'   => 'subsite-security-issues',
		'meta_compare' => 'LIKE',
		'fields'       => 'ID',
	) );

	if ( ! $users ) {
		return;
	}

	// Remove the value from the user meta.
	foreach ( $users as $user_id ) {
		SecuPress_Admin_Notices::reinit( 'subsite-security-issues', $user_id );
	}
}


/*------------------------------------------------------------------------------------------------*/
/* SCANS PAGE =================================================================================== */
/*------------------------------------------------------------------------------------------------*/

/**
 * Scanners page.
 *
 * @since 1.0
 */
function __secupress_subsite_scanners() {
	secupress_require_class( 'scan' );

	$class_name_parts = secupress_get_tests_for_ms_scanner_fixes();
	$sites            = secupress_get_results_for_ms_scanner_fixes();
	$site_id          = get_current_blog_id();
	$tests            = array();
	$heading_tag      = secupress_wp_version_is( '4.4-alpha' ) ? 'h2' : 'h3';

	foreach ( $sites as $test => $site_data ) {
		if ( ! empty( $site_data[ $site_id ] ) ) {
			$tests[ $test ] = $site_data[ $site_id ];
		}
	}
	?>
	<div class="wrap">
		<?php secupress_admin_heading( __( 'Scanners', 'secupress' ) ); ?>

		<div class="secupress-wrapper">
			<div id="secupress-tests">
				<div class="table-prio-all">
					<table class="wp-list-table widefat">
						<thead>
							<tr>
								<th scope="col" class="secupress-desc"><?php _e( 'Description', 'secupress' ); ?></th>
								<th scope="col" class="secupress-scan-status" data-sort="string"><?php _e( 'Scan Status', 'secupress' ); ?></th>
								<th scope="col" class=".secupress-scan-result"><?php _e( 'Scan Result', 'secupress' ); ?></th>
								<th scope="col" class="secupress-fix-status"><?php _e( 'Fix Status', 'secupress' ); ?></th>
								<th scope="col" class="secupress-fix-result"><?php _e( 'Fix Result', 'secupress' ); ?></th>
							</tr>
						</thead>

						<tfoot>
							<tr>
								<th scope="col" class="secupress-desc"><?php _e( 'Description', 'secupress' ); ?></th>
								<th scope="col" class="secupress-scan-status"><?php _e( 'Scan Status', 'secupress' ); ?></th>
								<th scope="col" class=".secupress-scan-result"><?php _e( 'Scan Result', 'secupress' ); ?></th>
								<th scope="col" class="secupress-fix-status"><?php _e( 'Fix Status', 'secupress' ); ?></th>
								<th scope="col" class="secupress-fix-result"><?php _e( 'Fix Result', 'secupress' ); ?></th>
							</tr>
						</tfoot>

						<tbody>
						<?php
						$i = 0;
						foreach ( $class_name_parts as $class_name_part ) {
							$option_name = strtolower( $class_name_part );

							if ( empty( $tests[ $option_name ] ) || ! file_exists( secupress_class_path( 'scan', $class_name_part ) ) ) {
								continue;
							}

							secupress_require_class( 'scan', $class_name_part );

							++$i;
							$class_name   = 'SecuPress_Scan_' . $class_name_part;
							$current_test = $class_name::get_instance()->for_current_site( true );
							$css_class    = ' type-' . sanitize_key( $class_name::$type );
							$css_class   .= $i % 2 === 0 ? '' : ' alternate';

							// Scan
							$status_text  = ! empty( $tests[ $option_name ]['scan']['status'] ) ? secupress_status( $tests[ $option_name ]['scan']['status'] )    : secupress_status( 'notscannedyet' );
							$status_class = ! empty( $tests[ $option_name ]['scan']['status'] ) ? sanitize_html_class( $tests[ $option_name ]['scan']['status'] ) : 'notscannedyet';
							$css_class   .= ' status-' . $status_class;
							$css_class   .= isset( $autoscans[ $class_name_part ] ) ? ' autoscan' : '';

							if ( ! empty( $tests[ $option_name ]['scan']['msgs'] ) ) {
								$scan_message = secupress_format_message( $tests[ $option_name ]['scan']['msgs'], $class_name_part );
							} else {
								$scan_message = '&#175;';
							}

							// Fix
							$fix_status_text  = ! empty( $tests[ $option_name ]['fix']['status'] ) && $tests[ $option_name ]['fix']['status'] !== 'good' ? secupress_status( $tests[ $option_name ]['fix']['status'] ) : '&#160;';
							$fix_css_class    = ! empty( $tests[ $option_name ]['fix']['status'] ) ? ' status-' . sanitize_html_class( $tests[ $option_name ]['fix']['status'] ) : ' status-cantfix';

							if ( ! empty( $tests[ $option_name ]['fix']['msgs'] ) && $status_class !== 'good' ) {
								$fix_message = secupress_format_message( $tests[ $option_name ]['fix']['msgs'], $class_name_part );
							} else {
								$fix_message = '';
							}
							?>
							<tr class="secupress-item-all secupress-item-<?php echo $class_name_part; ?> type-all status-all<?php echo $css_class; ?>">
								<th scope="row">
									<?php echo $class_name::$title; ?>
									<div class="secupress-row-actions">
										<span class="hide-if-no-js">
											<button type="button" class="secupress-details link-like" data-test="<?php echo $class_name_part; ?>" title="<?php esc_attr_e( 'Get details', 'secupress' ); ?>"><?php _e( 'Learn more', 'secupress' ); ?></button>
										</span>
									</div>
								</th>
								<td class="secupress-scan-status">
									<div class="secupress-status"><?php echo $status_text; ?></div>

									<div class="secupress-row-actions">
										<a class="button button-secondary button-small secupress-scanit" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?for-current-site=1&action=secupress_scanner&test=' . $class_name_part ), 'secupress_scanner_' . $class_name_part ); ?>"><?php _ex( 'Scan', 'scan a test', 'secupress' ); ?></a>
									</div>
								</td>
								<td class="secupress-scan-result">
									<?php echo $scan_message; ?>
								</td>
								<td class="secupress-fix-status<?php echo $fix_css_class; ?>">
									<div class="secupress-status"><?php echo $fix_status_text; ?></div>

									<div class="secupress-row-actions">
										<a class="button button-secondary button-small secupress-fixit" href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?for-current-site=1&action=secupress_fixit&test=' . $class_name_part ), 'secupress_fixit_' . $class_name_part ); ?>"><?php _e( 'Fix it!', 'secupress' ); ?></a>
									</div>
								</td>
								<td class="secupress-fix-result">
									<?php echo $fix_message; ?>
								</td>
							</tr>
							<?php
							if ( 0 && $class_name_part === $fix_actions[0] ) {
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
								<td colspan="5">
									<?php echo wp_kses_post( $current_test::$more ); ?>
								</td>
							</tr>
							<?php
						}
						?>
						</tbody>
					</table>

				</div>
			</div>
		</div>

	</div>
	<?php
}


/*------------------------------------------------------------------------------------------------*/
/* ACCESSING THE SETTINGS PAGE WHEN IT'S NOT AVAILABLE ========================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * On each site when all fixes are done, the settings page is not available anymore.
 * If the user refreshes the page, a "You do not have sufficient permissions to access this page" message will be shown: we need to display a better message.
 */
add_action( 'admin_page_access_denied', 'secupress_settings_page_access_denied_message' );

function secupress_settings_page_access_denied_message() {
	global $pagenow;
	if ( is_network_admin() || is_user_admin() || 'admin.php' !== $pagenow || empty( $_GET['page'] ) || 'secupress_scanners' !== $_GET['page'] ) {
		return;
	}
	if ( ! current_user_can( secupress_get_capability( true ) ) ) {
		return;
	}
	/* translators: %s is a link to the dashboard */
	$message = __( 'Since there are no other fixes to be done, this page does not exist anymore.<br/>You can go back to the %s.', 'secupress' );
	$link    = '<a href="' . esc_url( admin_url() ) . '">' . __( 'Dashboard' ) . '</a>';
	$title   = __( 'Back to the Dashboard', 'secupress' );
	// http code 403: "Forbidden".
	wp_die( sprintf( $message, $link ), $title, array( 'response' => 403 ) );
}


/*------------------------------------------------------------------------------------------------*/
/* ACTIVE PLUGINS AND THEMES ==================================================================== */
/*------------------------------------------------------------------------------------------------*/

/*
 * Use a site option to store the active plugins of each site.
 * Each time a blog option is added or modified, we store the new value in our network option.
 *
 * @since 1.0
 */
add_action( 'add_option_active_plugins',    'secupress_update_active_plugins_site_option', 20, 2 );
add_action( 'update_option_active_plugins', 'secupress_update_active_plugins_site_option', 20, 2 );

function secupress_update_active_plugins_site_option( $do_not_use = false, $value ) {
	$site_id = get_current_blog_id();
	$plugins = get_site_option( 'secupress_active_plugins' );

	// Don't go further until the first complete filling is done.
	if ( ! is_array( $plugins ) ) {
		return;
	}

	$value = $value ? $value                       : array();
	$value = $value ? array_fill_keys( $value, 1 ) : array();

	$plugins[ $site_id ] = $value;
	update_site_option( 'secupress_active_plugins', $plugins );
}


/*
 * Use a site option to store the active themes of each site.
 * Each time a blog option is added or modified, we store the new value in our network option.
 *
 * @since 1.0
 */
add_action( 'add_option_stylesheet',    'secupress_update_active_themes_site_option', 20, 2 );
add_action( 'update_option_stylesheet', 'secupress_update_active_themes_site_option', 20, 2 );

function secupress_update_active_themes_site_option( $do_not_use = false, $value ) {
	$site_id = get_current_blog_id();
	$themes  = get_site_option( 'secupress_active_themes' );

	// Don't go further until the first complete filling is done.
	if ( ! is_array( $themes ) ) {
		return;
	}

	$themes[ $site_id ] = $value;
	update_site_option( 'secupress_active_themes', $themes );
}


/*
 * When a blog is deleted, remove the corresponding row from the site options.
 *
 * @since 1.0
 */
add_action( 'delete_blog', 'secupress_delete_blog_from_active_plugins_and_themes_site_options', 20 );

function secupress_delete_blog_from_active_plugins_and_themes_site_options( $blog_id ) {
	$blog_id = (int) $blog_id;

	// Plugins
	$plugins = get_site_option( 'secupress_active_plugins' );

	if ( is_array( $plugins ) && isset( $plugins[ $blog_id ] ) ) {
		unset( $plugins[ $blog_id ] );
		update_site_option( 'secupress_active_plugins', $plugins );
	}

	// Themes
	$themes = get_site_option( 'secupress_active_themes' );

	if ( is_array( $themes ) && isset( $themes[ $blog_id ] ) ) {
		unset( $themes[ $blog_id ] );
		update_site_option( 'secupress_active_themes', $themes );
	}
}


/*
 * First complete filling.
 * If the network has more than 1000 sites, the options will be filled piece by piece.
 *
 * @since 1.0
 *
 * @return (int|bool) Until there are no more results to add, return the number of sites set so far. Return false otherwise.
 */
function secupress_fill_active_plugins_and_themes_site_options() {
	global $wpdb;
	$plugins = get_site_option( 'secupress_active_plugins' );

	// Don't go further if the first complete filling is already done and we don't need more results.
	if ( is_array( $plugins ) && empty( $plugins['offset'] ) ) {
		return false;
	}

	$themes  = get_site_option( 'secupress_active_themes' );
	$themes  = is_array( $themes )  ? $themes  : array();
	$plugins = is_array( $plugins ) ? $plugins : array();
	// Set the query boundaries.
	$offset  = ! empty( $plugins['offset'] ) ? absint( $plugins['offset'] ) : 0;
	$step    = apply_filters( 'secupress_fill_active_plugins_and_themes_site_options_step', 1 );
	$step    = absint( $step );
	$limit   = $offset * $step . ', ' . $step;

	$blogs   = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs WHERE site_id = %d LIMIT $limit", $wpdb->siteid ) );

	// Nothing? Bail out.
	if ( ! $blogs ) {
		if ( isset( $plugins['offset'] ) ) {
			unset( $plugins['offset'] );
			update_site_option( 'secupress_active_plugins', $plugins );
		}
		return false;
	}

	foreach ( $blogs as $blog_id ) {
		$blog_id      = (int) $blog_id;
		$table_prefix = $wpdb->get_blog_prefix( $blog_id );
		$blog_actives = $wpdb->get_results( "SELECT option_name, option_value FROM {$table_prefix}options WHERE option_name = 'active_plugins' OR option_name = 'stylesheet'", OBJECT_K );

		// Plugins
		$plugins[ $blog_id ] = ! empty( $blog_actives['active_plugins']->option_value ) ? unserialize( $blog_actives['active_plugins']->option_value ) : array();

		if ( $plugins[ $blog_id ] && is_array( $plugins[ $blog_id ] ) ) {
			$plugins[ $blog_id ] = array_fill_keys( $plugins[ $blog_id ], 1 );
		}

		// Themes
		$themes[ $blog_id ] = ! empty( $blog_actives['stylesheet']->option_value ) ? $blog_actives['stylesheet']->option_value : '';
	}

	// We need more results (or we are "unlucky").
	if ( count( $blogs ) === $step ) {
		$plugins['offset'] = ( ++$offset );
		// Update our options.
		update_site_option( 'secupress_active_plugins', $plugins );
		update_site_option( 'secupress_active_themes', $themes );
		// Return the number of sites set so far.
		return count( $plugins ) - 1;
	}

	// Done!
	unset( $plugins['offset'] );
	update_site_option( 'secupress_active_plugins', $plugins );
	update_site_option( 'secupress_active_themes', $themes );
	return false;
}


/*
 * When the user reaches the scans page, display a message if our options need more results.
 *
 * @since 1.0
 */
add_action( 'load-secupress_page_secupress_scanners', 'secupress_add_active_plugins_and_themes_site_options' );

function secupress_add_active_plugins_and_themes_site_options() {
	if ( secupress_fill_active_plugins_and_themes_site_options() ) {
		$message = sprintf(
			/* translators: %s is a "click here" link. */
			__( 'Your network is quite big. Before doing anything, some data must be set. Please %s.', 'secupress' ),
			'<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress-set-big-data&_wp_http_referer=' . esc_url( secupress_get_current_url( 'raw' ) ) ), 'secupress-set-big-data' ) . '" class="secupress-set-big-data">' . __( 'click here', 'secupress' ) . '</a>'
		);
		secupress_add_notice( $message, 'error', false );
	}
}


/*
 * Add more results when the user clicks the link.
 * This is used when JS is enabled in the user's browser.
 *
 * @since 1.0
 */
add_action( 'wp_ajax_secupress-set-big-data', 'secupress_add_active_plugins_and_themes_site_options_admin_ajax_callback' );

function secupress_add_active_plugins_and_themes_site_options_admin_ajax_callback() {
	global $wpdb;

	if ( ! check_ajax_referer( 'secupress-set-big-data', false, false ) ) {
		wp_send_json_error();
	}

	if ( ! current_user_can( secupress_get_capability() ) ) {
		wp_send_json_error();
	}

	if ( ! ( $count = secupress_fill_active_plugins_and_themes_site_options() ) ) {
		wp_send_json_success( false );
	}

	$total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT( blog_id ) FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );
	$percent = ceil( $count * 100 / max( $total, 1 ) );
	wp_send_json_success( $percent );
}


/*
 * Add more results when the user clicks the link.
 * This is used when JS is disabled in the user's browser: we display a small window with auto-refresh.
 *
 * @since 1.0
 */
add_action( 'admin_post_secupress-set-big-data', 'secupress_add_active_plugins_and_themes_site_options_admin_post_callback' );

function secupress_add_active_plugins_and_themes_site_options_admin_post_callback() {
	global $wpdb;

	check_admin_referer( 'secupress-set-big-data' );

	if ( ! current_user_can( secupress_get_capability() ) ) {
		wp_nonce_ays( '' );
	}

	if ( ! ( $count = secupress_fill_active_plugins_and_themes_site_options() ) ) {
		wp_safe_redirect( wp_get_referer() );
		die();
	}

	$total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT( blog_id ) FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );
	$percent = ceil( $count * 100 / max( $total, 1 ) );
	?><!DOCTYPE html>
<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php echo esc_attr( strtolower( get_bloginfo( 'charset' ) ) ); ?>" />
		<title><?php _e( 'Setting new data...', 'secupress' ); ?></title>
		<meta content="initial-scale=1.0" name="viewport" />
		<meta http-equiv="refresh" content="1" />
		<style>
html, body {
	width: 100%;
	margin: 0;
	font: 1em/1.5 Arial, Helvetica, sans-serif;
	color: #313131;
	background: #F1F1F1;
}
.wrap {
	max-width: 400px;
	padding: 20px 10px;
	margin: 10px auto;
	text-align: center;
}
.progress-wrap {
	width: 100%;
	border: solid 1px #555;
	margin-left: -1px;
}
.progress {
	height: 1.5em;
	line-height: 1.5em;
	background: #88BA0E;
	color: #fff;
	font-size: 2em;
	font-weight: 700;
	text-align: center;
}
a {
	color: #205081;
}
a:active,
a:hover,
a:focus {
	color: #2d75bd;
}
		</style>
	</head>
	<body>
		<div class="wrap">
			<p><?php
			printf(
				/* translators: %s is a "click here" link. */
				__( 'If this page does not refresh automatically in 2 seconds, please %s.', 'secupress' ),
				'<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress-set-big-data&_wp_http_referer=' . esc_url( wp_get_referer() ) ), 'secupress-set-big-data' ) . '" class="secupress-set-big-data">' . __( 'click here', 'secupress' ) . '</a>'
			);
			?></p>
			<div class="progress-wrap"><div style="width: <?php echo $percent; ?>%;" class="progress"><?php echo $percent; ?>%</div></div>
		</div>
	</body>
</html><?php
	die();
}
