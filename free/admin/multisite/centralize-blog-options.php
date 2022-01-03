<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** ACTIVE PLUGINS AND THEMES =================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'add_option_active_plugins',    'secupress_update_active_plugins_centralized_blog_option', 20, 2 );
add_action( 'update_option_active_plugins', 'secupress_update_active_plugins_centralized_blog_option', 20, 2 );
/**
 * Use a site option to store the active plugins of each site.
 * Each time a blog option is added or modified, we store the new value in our network option.
 *
 * @since 1.0
 *
 * @param (mixed) $do_not_use The old option value or the name of the option (depending on the hook).
 * @param (mixed) $value      The value of the option.
 */
function secupress_update_active_plugins_centralized_blog_option( $do_not_use, $value ) {
	$site_id = get_current_blog_id();
	$plugins = get_site_option( 'secupress_active_plugins' );

	// Don't go further until the first complete filling is done.
	if ( ! is_array( $plugins ) ) {
		return;
	}

	$value = $value ? array_fill_keys( $value, 1 ) : array();

	$plugins[ $site_id ] = $value;
	update_site_option( 'secupress_active_plugins', $plugins );
}


add_action( 'add_option_stylesheet',    'secupress_update_active_themes_centralized_blog_option', 20, 2 );
add_action( 'update_option_stylesheet', 'secupress_update_active_themes_centralized_blog_option', 20, 2 );
/**
 * Use a site option to store the active themes of each site.
 * Each time a blog option is added or modified, we store the new value in our network option.
 *
 * @since 1.0
 *
 * @param (mixed) $do_not_use The old option value or the name of the option (depending on the hook).
 * @param (mixed) $value      The value of the option.
 */
function secupress_update_active_themes_centralized_blog_option( $do_not_use, $value ) {
	$site_id = get_current_blog_id();
	$themes  = get_site_option( 'secupress_active_themes' );

	// Don't go further until the first complete filling is done.
	if ( ! is_array( $themes ) ) {
		return;
	}

	$themes[ $site_id ] = $value;
	update_site_option( 'secupress_active_themes', $themes );
}


add_action( 'add_option_default_role',    'secupress_update_default_role_centralized_blog_option', 20, 2 );
add_action( 'update_option_default_role', 'secupress_update_default_role_centralized_blog_option', 20, 2 );
/**
 * Use a site option to store the default user role of each site.
 * Each time a blog option is added or modified, we store the new value in our network option.
 *
 * @since 1.0
 *
 * @param (mixed) $do_not_use The old option value or the name of the option (depending on the hook).
 * @param (mixed) $value      The value of the option.
 */
function secupress_update_default_role_centralized_blog_option( $do_not_use, $value ) {
	$site_id = get_current_blog_id();
	$roles   = get_site_option( 'secupress_default_role' );

	// Don't go further until the first complete filling is done.
	if ( ! is_array( $roles ) ) {
		return;
	}

	$roles[ $site_id ] = $value;
	update_site_option( 'secupress_default_role', $roles );
}


add_action( 'delete_blog', 'secupress_delete_blog_from_centralized_blog_options', 20 );
/**
 * When a blog is deleted, remove the corresponding row from the site options.
 *
 * @since 1.0
 *
 * @param (int) $blog_id The blog ID.
 */
function secupress_delete_blog_from_centralized_blog_options( $blog_id ) {
	$blog_id = (int) $blog_id;

	// Plugins.
	$plugins = get_site_option( 'secupress_active_plugins' );

	if ( is_array( $plugins ) && isset( $plugins[ $blog_id ] ) ) {
		unset( $plugins[ $blog_id ] );
		update_site_option( 'secupress_active_plugins', $plugins );
	}

	// Themes.
	$themes = get_site_option( 'secupress_active_themes' );

	if ( is_array( $themes ) && isset( $themes[ $blog_id ] ) ) {
		unset( $themes[ $blog_id ] );
		update_site_option( 'secupress_active_themes', $themes );
	}

	// Default user role.
	$themes = get_site_option( 'secupress_default_role' );

	if ( is_array( $themes ) && isset( $themes[ $blog_id ] ) ) {
		unset( $themes[ $blog_id ] );
		update_site_option( 'secupress_default_role', $themes );
	}
}


/** --------------------------------------------------------------------------------------------- */
/** FILL IN THE FIRST VALUES ==================================================================== */
/** --------------------------------------------------------------------------------------------- */

add_action( 'load-toplevel_page_' . SECUPRESS_PLUGIN_SLUG . '_scanners', 'secupress_add_centralized_blog_options' );
/**
 * When the user reaches the scans page, display a message if our options need more results.
 *
 * @since 1.0
 */
function secupress_add_centralized_blog_options() {
	if ( ! secupress_fill_centralized_blog_options() ) {
		return;
	}

	$href = urlencode( esc_url_raw( secupress_get_current_url( 'raw' ) ) );
	$href = admin_url( 'admin-post.php?action=secupress-centralize-blog-options&_wp_http_referer=' . $href );
	$href = wp_nonce_url( $href, 'secupress-centralize-blog-options' );

	$message = sprintf(
		/** Translators: %s is a "click here" link. */
		__( 'Your network is quite big. Before doing anything, some data must be set. Please %s.', 'secupress' ),
		'<a href="' . esc_url( $href ) . '" class="secupress-centralize-blog-options">' . __( 'click here', 'secupress' ) . '</a>'
	);
	secupress_add_notice( $message, 'error', false );
}


add_action( 'wp_ajax_secupress-centralize-blog-options', 'secupress_add_centralized_blog_options_admin_ajax_callback' );
/**
 * Add more results when the user clicks the link.
 * This is used when JS is enabled in the user's browser.
 *
 * @since 1.0
 */
function secupress_add_centralized_blog_options_admin_ajax_callback() {
	global $wpdb;

	secupress_check_admin_referer( 'secupress-centralize-blog-options' );
	secupress_check_user_capability();

	if ( ! ( $count = secupress_fill_centralized_blog_options() ) ) {
		wp_send_json_success( false );
	}

	$total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT( blog_id ) FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );
	$percent = ceil( $count * 100 / max( $total, 1 ) );
	wp_send_json_success( $percent );
}


add_action( 'admin_post_secupress-centralize-blog-options', 'secupress_add_centralized_blog_options_admin_post_callback' );
/**
 * Add more results when the user clicks the link.
 * This is used when JS is disabled in the user's browser: we display a small window with auto-refresh.
 *
 * @since 1.0
 */
function secupress_add_centralized_blog_options_admin_post_callback() {
	global $wpdb;

	secupress_check_admin_referer( 'secupress-centralize-blog-options' );
	secupress_check_user_capability();

	if ( ! ( $count = secupress_fill_centralized_blog_options() ) ) {
		wp_safe_redirect( esc_url_raw( wp_get_referer() ) );
		die();
	}

	$total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT( blog_id ) FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );
	$percent = ceil( $count * 100 / max( $total, 1 ) );
	$href    = urlencode( esc_url_raw( wp_get_referer() ) );
	$href    = admin_url( 'admin-post.php?action=secupress-centralize-blog-options&_wp_http_referer=' . $href );
	$href    = wp_nonce_url( $href, 'secupress-centralize-blog-options' );

	ob_start();
	?>
	<div class="wrap">
		<p>
			<?php
			printf(
				/** Translators: %s is a "click here" link. */
				__( 'If this page does not refresh automatically in 2 seconds, please %s.', 'secupress' ),
				/** For `wp_get_referer()` see the param `_wp_http_referer` in `secupress_add_centralized_blog_options()`. */
				'<a href="' . esc_url( $href ) . '" class="secupress-centralize-blog-options">' . __( 'click here', 'secupress' ) . '</a>'
			);
			?>
		</p>
		<div class="progress-wrap"><div style="width:<?php echo $percent; ?>%" class="progress"><?php echo $percent; ?>%</div></div>
	</div>
	<?php
	$title   = __( 'Setting new data&hellip;', 'secupress' );
	$content = ob_get_contents();
	$args    = array( 'head' => '<meta http-equiv="refresh" content="1" />' );
	ob_clean();

	secupress_action_page( $title, $content, $args );
}


/** --------------------------------------------------------------------------------------------- */
/** TOOLS ======================================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * First complete filling.
 * If the network has more than 250 sites, the options will be filled piece by piece.
 *
 * @since 1.0
 *
 * @return (int|bool) Until there are no more results to add, return the number of sites set so far. Return false otherwise.
 */
function secupress_fill_centralized_blog_options() {
	global $wpdb;
	$plugins = get_site_option( 'secupress_active_plugins' );

	// Don't go further if the first complete filling is already done and we don't need more results.
	if ( is_array( $plugins ) && empty( $plugins['offset'] ) ) {
		return false;
	}

	$themes  = get_site_option( 'secupress_active_themes' );
	$roles   = get_site_option( 'secupress_default_role' );
	$plugins = is_array( $plugins ) ? $plugins : array();
	$themes  = is_array( $themes )  ? $themes  : array();
	$roles   = is_array( $roles )   ? $roles   : array();
	// Set the query boundaries.
	$offset  = ! empty( $plugins['offset'] ) ? absint( $plugins['offset'] ) : 0;
	/**
	 * Filter query step: the number of blogs from where we'll be fetch data.
	 *
	 * @since 1.0
	 *
	 * @param (int) $step Default is 250.
	 */
	$step    = apply_filters( 'secupress.multisite.fill_centralized_blog_options_step', 250 );
	$step    = absint( $step );
	$limit   = $offset * $step . ', ' . $step;

	$blogs   = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs WHERE site_id = %d LIMIT $limit", $wpdb->siteid ) ); // WPCS: unprepared SQL ok.

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
		$blog_actives = $wpdb->get_results( "SELECT option_name, option_value FROM {$table_prefix}options WHERE option_name = 'active_plugins' OR option_name = 'stylesheet' OR option_name = 'default_role'", OBJECT_K ); // WPCS: unprepared SQL ok.

		// Plugins.
		$plugins[ $blog_id ] = ! empty( $blog_actives['active_plugins']->option_value ) ? unserialize( $blog_actives['active_plugins']->option_value ) : array();

		if ( $plugins[ $blog_id ] && is_array( $plugins[ $blog_id ] ) ) {
			$plugins[ $blog_id ] = array_fill_keys( $plugins[ $blog_id ], 1 );
		}

		// Themes.
		$themes[ $blog_id ] = ! empty( $blog_actives['stylesheet']->option_value ) ? $blog_actives['stylesheet']->option_value : '';

		// Default user role.
		$roles[ $blog_id ] = ! empty( $blog_actives['default_role']->option_value ) ? $blog_actives['default_role']->option_value : '';
	}

	// We need more results (or we are "unlucky").
	if ( count( $blogs ) === $step ) {
		// We temporarely store the last offset in the "active plugins" option.
		$plugins['offset'] = ( ++$offset );
		// Update our options.
		update_site_option( 'secupress_active_plugins', $plugins );
		update_site_option( 'secupress_active_themes', $themes );
		update_site_option( 'secupress_default_role', $roles );
		// Return the number of sites set so far.
		return count( $plugins ) - 1;
	}

	// Done!
	unset( $plugins['offset'] );
	update_site_option( 'secupress_active_plugins', $plugins );
	update_site_option( 'secupress_active_themes', $themes );
	update_site_option( 'secupress_default_role', $roles );
	return false;
}
