<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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
				/* For `wp_get_referer()` see the param `_wp_http_referer` in `secupress_add_active_plugins_and_themes_site_options()`. */
				'<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress-set-big-data&_wp_http_referer=' . esc_url( wp_get_referer() ) ), 'secupress-set-big-data' ) . '" class="secupress-set-big-data">' . __( 'click here', 'secupress' ) . '</a>'
			);
			?></p>
			<div class="progress-wrap"><div style="width: <?php echo $percent; ?>%;" class="progress"><?php echo $percent; ?>%</div></div>
		</div>
	</body>
</html><?php
	die();
}
