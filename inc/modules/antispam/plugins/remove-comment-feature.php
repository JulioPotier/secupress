<?php
/*
Module Name: Remove Comment Feature
Description: Remove comments support. Cleanup administration.
Main Module: antispam
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );

/* !---------------------------------------------------------------------------- */
/* !	UTILITIES																 */
/* ----------------------------------------------------------------------------- */

// !Return the post types supporting comments.

function secupress_nocomment_get_post_types_supporting_comments() {
	global $_wp_post_type_features;

	$post_types = array();
	foreach ( $_wp_post_type_features as $type => $features ) {
		if ( ! empty( $features['comments'] ) ) {
			$post_types[ $type ] = $type;
		}
	}

	// Store the post types originally supporting comments. This info can be used later if needed.
	secupress_nocomment_get_comments_original_support( $post_types );

	return $post_types;
}


// !Return the post types originally supporting comments (before the support is removed).

function secupress_nocomment_get_comments_original_support( $array = null ) {
	static $post_types;

	if ( ! isset( $post_types ) ) {
		$post_types = $array;
	}

	return $post_types;
}


// !Return the post types to remove comments support from.

function secupress_nocomment_post_type_supports() {
	$post_types = secupress_nocomment_get_post_types_supporting_comments();
	$post_types = (array) apply_filters( 'no_comments_post_type_supports', $post_types );
	$post_types = array_filter( array_flip( array_flip( $post_types ) ) );

	return $post_types;
}


// !Check if a plugin is activated for a certain blog

if ( ! function_exists( 'is_plugin_active_for_blog' ) ) :
function is_plugin_active_for_blog( $plugin, $blog_id ) {
	if ( function_exists( 'is_plugin_active_for_network' ) ) {
		$is_plugin_active_for_network = is_plugin_active_for_network( $plugin );
	} elseif ( ! is_multisite() ) {
		$is_plugin_active_for_network = false;
	} else {
		$plugins = get_site_option( 'active_sitewide_plugins');
		$is_plugin_active_for_network = isset( $plugins[ $plugin ] );
	}
	return in_array( $plugin, (array) get_blog_option( $blog_id, 'active_plugins', array() ) ) || $is_plugin_active_for_network;
}
endif;


/* !---------------------------------------------------------------------------- */
/* !	INIT																	 */
/* ----------------------------------------------------------------------------- */

// !Remove comments support and launch filters.

add_action( 'init', 'secupress_nocomment_init', PHP_INT_MAX );
function secupress_nocomment_init() {
	$types = secupress_nocomment_post_type_supports();

	if ( count( $types ) ) {
		foreach ( $types as $type ) {
			remove_post_type_support( $type, 'comments' );
		}
	}

	$types = secupress_nocomment_get_post_types_supporting_comments();

	if ( empty( $types ) ) {

		if ( is_admin() ) {
			// Hide the comments section in the "Today" dashboard widget
			add_action( 'admin_head', 'secupress_nocomment_today_widget' );

			// Removes the "Recent comments" dashboard widget and the menu item
			add_action( 'admin_menu', 'secupress_nocomment_dashboard_widget_and_menu' );
		}
		else {
			// Deregister the "comment-reply" script in frontend.
			wp_deregister_script( 'comment-reply' );

			// Remove comments feed link from head.
			remove_action( 'wp_head', 'feed_links_extra', 3 );
		}

		// Adminbar: removes the general comments item and the site specific comments item for multisite
		add_action( 'add_admin_bar_menus', 'secupress_nocomment_admin_bar_menus' );

		// Remove the "Recent Comments" widget
		unregister_widget( 'WP_Widget_Recent_Comments' );

		// Make sure comments and pings are really open (or closed)
		add_filter( 'comments_open', 'secupress_nocomment_comments_open', 10, 2 );
		add_filter( 'pings_open', 'secupress_nocomment_comments_open', 10, 2 );

		// Filter default options to return "closed"
		add_filter( 'pre_option_default_comment_status', 'secupress_nocomment_return_closed' );
		add_filter( 'pre_option_default_ping_status', 'secupress_nocomment_return_closed' );
	}
}


/* !---------------------------------------------------------------------------- */
/* !	ADMIN																	 */
/* ----------------------------------------------------------------------------- */

// !Hide the comments section in the "Today" dashboard widget

function secupress_nocomment_today_widget() {
	$screen = get_current_screen();

	if ( ! empty( $screen->id ) && $screen->id === 'dashboard' ) {
		echo '<style type="text/css">.table_discussion,.comment-count,.comment-mod-count,#latest-comments{display:none;}</style>';
	}
}


// !Remove the "Recent comments" dashboard widget and the menu item

function secupress_nocomment_dashboard_widget_and_menu() {
	remove_menu_page( 'edit-comments.php' );
	remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'core' );
}


/* !---------------------------------------------------------------------------- */
/* !	ADMINBAR																 */
/* ----------------------------------------------------------------------------- */


// !Adminbar: remove the general comments item and the site specific comments item for multisite

function secupress_nocomment_admin_bar_menus() {
	add_action( 'admin_bar_menu',    'secupress_nocomment_admin_bar_blogs_list',   40 );
	remove_action( 'admin_bar_menu', 'wp_admin_bar_comments_menu', 60 );
}


// !Remove the site specific comments item (admin bar) for multisite.

function secupress_nocomment_admin_bar_blogs_list( $wp_admin_bar ) {
	if ( ! is_multisite() ) {
		return;
	}

	if ( count( $wp_admin_bar->user->blogs ) < 1 || ! is_super_admin() ) {
		return;
	}

	$nodes  = $wp_admin_bar->get_nodes();
	$plugin = plugin_basename( __FILE__ );

	foreach ( (array) $wp_admin_bar->user->blogs as $blog ) {
		$menu_id = 'blog-' . $blog->userblog_id;

		if ( isset( $nodes[ $menu_id ] ) && is_plugin_active_for_blog( $plugin, $blog->userblog_id ) ) {
			$wp_admin_bar->remove_node( $menu_id . '-c' );
		}
	}
}


/* !---------------------------------------------------------------------------- */
/* !	OTHER STUFF																 */
/* ----------------------------------------------------------------------------- */

// !Make sure comments and pings are really open (or closed)

function secupress_nocomment_comments_open( $open, $post_id ) {
	$_post = get_post( $post_id );
	return $open && ! empty( $_post->post_type ) && post_type_supports( $_post->post_type, 'comments' );
}


// !Filter default options to return "closed"

function secupress_nocomment_return_closed() {
	return 'closed';
}