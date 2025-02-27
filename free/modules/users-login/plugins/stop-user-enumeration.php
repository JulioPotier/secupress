<?php
/**
 * Module Name: Stop User Enumeration
 * Description: Forbid the user listing from front with ?author=X and from REST API with /users/
 * Main Module: users_login
 * Author: SecuPress
 * Version: 2.2.6
 */

defined( 'SECUPRESS_VERSION' ) or die( 'Something went wrong.' );

add_action( 'wp', 'secupress_set_404_for_author_pages' );
/**
 * Returns a 404 when an author page is loaded
 *
 * @since 2.2.6 remove_action to prevent a WP warning due to a lack of index check...
 * @since 1.0
 * @author Julio Potier
 **/
function secupress_set_404_for_author_pages() {
	global $wp_query;
	if ( is_author() ) {
		remove_action( 'template_redirect', 'redirect_canonical' );
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
		secupress_die( __( 'Sorry, you are not allowed to do that.', 'secupress' ), '', [ 'response' => 403, 'force_die' => true, 'attack_type' => 'users' ] );
	}
}


add_filter( 'rest_request_before_callbacks', 'secupress_stop_user_enumeration_rest' );
/**
 * Block the author page for REST API
 *
 * @param WP_Error|null   $response The current error object if any.
 * *
 * @since 2.2.6 Remove home_url() from strpos()
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
		strpos( rawurldecode( secupress_get_current_url( 'raw' ) ), $rest_base_url ) === 0 ||
		strpos( rawurldecode( secupress_get_current_url( 'raw' ) ), $rest_query_url ) !== false )
	) {
		wp_send_json( array( 'code' => 'rest_cannot_access', 'message' => __( 'Something went wrong.', 'secupress' ), 'data' => [ 'status' => 401 ] ) , 401 );
	}
    return $response;
}
