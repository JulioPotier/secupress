<?php
/**
 * Module Name: Stop User Enumeration
 * Description: Forbid the user listing from front with ?author=X and from REST API with /users/
 * Main Module: users_login
 * Author: SecuPress
 * Version: 1.0
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'template_redirect', 'secupress_set_404_for_author_pages' );
/**
 * Returns a 404 when an author page is loaded
 *
 * @since 1.0
 * @return void
 * @author Julio Potier
 **/
function secupress_set_404_for_author_pages() {
	global $wp_query;
	if ( is_author() ) {
		$wp_query->set_404();
		status_header( 404 );
	}
}

add_filter( 'author_link', 'secupress_replace_author_link' );
/**
 * Replace the author links with homepage to prevent linking on 404 pages
 *
 * @since 1.0
 * @return (string) home_url()
 * @author Julio Potier
 **/
function secupress_replace_author_link() {
	return home_url();
}

/**
 * Protected means that only descendants of the Code class can access that property so it must be public.
 *
 * @since 1.0
 * @author Julio Potier
 **/
class Secupress_WP_REST_Users_Controller extends WP_REST_Users_Controller {
	/**
	 * Return the rest base URL.
	 *
	 * @return string
	 * @author Julio Potier
	 **/
	public static function get_rest_base() {
		$controller = new Secupress_WP_REST_Users_Controller();
		return untrailingslashit( $controller->namespace . '/' . $controller->rest_base );
	}
}

add_action( 'init', 'secupress_stop_user_enumeration_front', SECUPRESS_INT_MAX );
/**
 * Block the author page on front
 *
 * @since 1.0
 * @author Julio Potier
 **/
function secupress_stop_user_enumeration_front() {
	if ( ! current_user_can( 'list_users' ) && is_author() ) {
		secupress_die( __( 'Sorry, you are not allowed to do that.', 'secupress' ), '', array( 'response' => 403, 'force_die' => true ) );
	}
}


add_filter( 'rest_request_before_callbacks', 'secupress_stop_user_enumeration_rest' );
/**
 * Block the author page for REST API
 *
 * @param WP_Error|null   $response The current error object if any.
 * *
 * @since 2.2.5 Remove REST API calls made using query parameters + usage of rawurldecode()
 * @since 2.2.2 'raw'
 * @since 2.0 'uri'
 * @since 1.0 'base'
 * @author Julio Potier
 **/
function secupress_stop_user_enumeration_rest( $response ) {
	$rest_base_url  = home_url( 'wp-json/' . Secupress_WP_REST_Users_Controller::get_rest_base() );
	$rest_query_url = 'rest_route=/wp/v2/users';
	if ( ! current_user_can( 'list_users' ) && (
		strpos( rawurldecode( home_url( secupress_get_current_url( 'raw' ) ) ), $rest_base_url ) === 0 ||
		strpos( rawurldecode( home_url( secupress_get_current_url( 'raw' ) ) ), $rest_query_url ) !== false )
	) {
		wp_send_json( array( 'code' => 'rest_cannot_access', 'message' => __( 'Something went wrong.', 'secupress' ), 'data' => array( 'status' => 401 ) ) , 401 );
	}
    return $response;
}
