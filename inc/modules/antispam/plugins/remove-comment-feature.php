<?php
/**
 * Module Name: Remove Comment Feature
 * Description: Remove comments support. Cleanup administration.
 * Main Module: antispam
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** INIT ======================================================================================== */
/** ----------------------------------------------------------------------------------------------*/

add_action( 'init', 'secupress_nocomment_init', PHP_INT_MAX );
/**
 * Remove comments support and launch filters.
 *
 * @since 1.0
 */
function secupress_nocomment_init() {
	// Get post types that support comments.
	$post_types_raw = secupress_nocomment_get_post_types_supporting_comments();

	/**
	 * Store the post types originally supporting comments.
	 * This info can be used later if needed.
	 */
	secupress_cache_data( 'nocomment_post_types', $post_types_raw );

	/**
	 * Filter the post types which comments support will be removed from.
	 *
	 * @since 1.0
	 *
	 * @param (array) $post_types_raw List of Post types. An array like `array( "post" => "post", "attachment" => "attachment" )`.
	 */
	$post_types = (array) apply_filters( 'no_comments_post_type_supports', $post_types_raw );
	$post_types = array_filter( $post_types );

	if ( ! $post_types ) {
		return;
	}

	$post_types = array_flip( array_flip( $post_types ) );

	foreach ( $post_types as $post_type ) {
		remove_post_type_support( $post_type, 'comments' );
	}

	if ( array_diff( $post_types_raw, $post_types ) ) {
		return;
	}

	if ( is_admin() ) {
		// Hide the comments section in the "Today" dashboard widget.
		add_action( 'admin_head', 'secupress_nocomment_today_widget' );

		// Remove the "Recent comments" dashboard widget and the menu item.
		add_action( 'admin_menu', 'secupress_nocomment_dashboard_widget_and_menu' );
	}
	else {
		// Deregister the "comment-reply" script in frontend.
		wp_deregister_script( 'comment-reply' );

		// Remove comments feed link from head.
		remove_action( 'wp_head', 'feed_links_extra', 3 );
	}

	// Adminbar: remove the general comments item and the site specific comments item for multisite.
	add_action( 'add_admin_bar_menus', 'secupress_nocomment_admin_bar_menus' );

	// Remove the "Recent Comments" widget.
	unregister_widget( 'WP_Widget_Recent_Comments' );

	// Filter whether the current post is open for comments and pings.
	add_filter( 'comments_open', 'secupress_nocomment_comments_open', 10, 2 );
	add_filter( 'pings_open',    'secupress_nocomment_comments_open', 10, 2 );

	// Filter default comments/pings to return "closed".
	add_filter( 'pre_option_default_comment_status', 'secupress_nocomment_return_closed' );
	add_filter( 'pre_option_default_ping_status',    'secupress_nocomment_return_closed' );
}


/** --------------------------------------------------------------------------------------------- */
/** ADMIN ======================================================================================= */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Print some CSS to hide the comments section in the "Today" dashboard widget.
 *
 * @since 1.0
 */
function secupress_nocomment_today_widget() {
	$screen = get_current_screen();

	if ( ! empty( $screen->id ) && 'dashboard' === $screen->id ) {
		echo '<style type="text/css">.table_discussion,.comment-count,.comment-mod-count,#latest-comments{display:none;}</style>';
	}
}


/**
 * Remove the "Recent comments" dashboard widget and the menu item.
 *
 * @since 1.0
 */
function secupress_nocomment_dashboard_widget_and_menu() {
	remove_menu_page( 'edit-comments.php' );
	remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'core' );
}


/** --------------------------------------------------------------------------------------------- */
/** ADMINBAR ==================================================================================== */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Adminbar: remove the general comments item and the site specific comments item for multisite.
 *
 * @since 1.0
 */
function secupress_nocomment_admin_bar_menus() {
	add_action( 'admin_bar_menu', 'secupress_nocomment_admin_bar_blogs_list', 40 );
	remove_action( 'admin_bar_menu', 'wp_admin_bar_comments_menu', 60 );
}


/**
 * Remove the site specific comments item (admin bar) for multisite.
 *
 * @since 1.0
 *
 * @param (object) $wp_admin_bar The `WP_Admin_Bar` object.
 */
function secupress_nocomment_admin_bar_blogs_list( $wp_admin_bar ) {
	// Don't show for logged out users or single site mode.
	if ( ! is_user_logged_in() || ! is_multisite() ) {
		return;
	}

	// Show only when the user has at least one site, or they're a super admin.
	if ( ! $wp_admin_bar->user->blogs && ! is_super_admin() ) {
		return;
	}

	$nodes = $wp_admin_bar->get_nodes();

	foreach ( (array) $wp_admin_bar->user->blogs as $blog ) {
		$menu_id = 'blog-' . $blog->userblog_id . '-c';

		if ( isset( $nodes[ $menu_id ] ) ) {
			$wp_admin_bar->remove_node( $menu_id );
		}
	}
}


/** --------------------------------------------------------------------------------------------- */
/** OTHER FILTERS =============================================================================== */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Filter whether the current post is open for comments/pings.
 * If the Post post type doesn't support comments, tell that comments/pings are closed.
 *
 * @since 1.0
 *
 * @param (bool)        $open    Whether the current post is open for comments/pings.
 * @param (int|WP_Post) $post_id The post ID or WP_Post object.
 */
function secupress_nocomment_comments_open( $open, $post_id ) {
	$post = get_post( $post_id );
	return $open && $post && post_type_supports( $post->post_type, 'comments' );
}


/**
 * Filter default comments/pings to return "closed".
 *
 * @since 1.0
 *
 * @return (string) Value to return instead of the option value.
 */
function secupress_nocomment_return_closed() {
	return 'closed';
}


/** --------------------------------------------------------------------------------------------- */
/** UTILITIES =================================================================================== */
/** ----------------------------------------------------------------------------------------------*/

/**
 * Get the post types supporting comments.
 *
 * @since 1.0
 *
 * @return (array) Post types that supports comments.
 */
function secupress_nocomment_get_post_types_supporting_comments() {
	global $_wp_post_type_features;

	$post_types = array();

	foreach ( $_wp_post_type_features as $type => $features ) {
		if ( ! empty( $features['comments'] ) ) {
			$post_types[ $type ] = $type;
		}
	}

	return $post_types;
}


/**
 * Get the post types originally supporting comments (before the support is removed).
 *
 * @since 1.0
 *
 * @return (array) Stored post types.
 */
function secupress_nocomment_get_comments_original_support() {
	return secupress_cache_data( 'nocomment_post_types' );
}
