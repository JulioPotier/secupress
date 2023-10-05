<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/** --------------------------------------------------------------------------------------------- */
/** AJAX AND POST HELPERS ======================================================================= */
/** --------------------------------------------------------------------------------------------- */

/**
 * A simple shorthand to `die()`, depending on the admin context.
 *
 * @since 1.0
 * @since 1.2.4 Added `$data` parameter.
 *
 * @param (string|object) $data A message to display or a WP_Error object.
 */
function secupress_admin_die( $data = null ) {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_error( $data );
	}

	if ( ! $data ) {
		wp_nonce_ays( '' );
	}

	if ( is_wp_error( $data ) ) {
		$result = array();

		foreach ( $data->errors as $messages ) {
			foreach ( $messages as $message ) {
				$result[] = $message;
			}
		}

		$data = implode( '</p><p>', $result );

		if ( wp_get_referer() ) {
			$data .= '</p><p>';
			$data .= sprintf( '<a href="%s">%s</a>',
				esc_url( wp_get_referer() ),
				__( 'Please try again.', 'secupress' )
			);
		}
	}

	wp_die( $data, __( 'WordPress Failure Notice', 'secupress' ), 403 );
}


/**
 * A simple shorthand to send a json response, die, or redirect to one of our settings pages, depending on the admin context.
 *
 * @since 1.0
 *
 * @param (array)  $response A scan/fix result or false.
 * @param (string) $redirect One of our pages slug. Can include an URL identifier (#azerty). If omitted, the referrer is used.
 */
function secupress_admin_send_response_or_redirect( $response = false, $redirect = false ) {
	if ( ! $response ) {
		secupress_admin_die( 'Missing $response in ' . __FUNCTION__ ); // Do not translate.
	}

	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		wp_send_json_success( $response );
	}

	if ( $redirect ) {
		$redirect = explode( '#', $redirect );
		$redirect = secupress_admin_url( $redirect[0] ) . ( ! empty( $redirect[1] ) ? '#' . $redirect[1] : '' );
	} else {
		$redirect = wp_get_referer();
	}

	wp_redirect( esc_url_raw( $redirect ) );
	die();
}


/**
 * A simple shorthand to send a json response with message, die, or redirect with a message, depending on the admin context.
 *
 * @since 1.0
 *
 * @param (array) $args An array of arguments like:
 *                      (string)      $message     The message to return.
 *                      (string|bool) $redirect_to The URL to redirect to: false for the referer, or a complete URL, or the slug of one of our settings pages.
 *                      (string)      $code        An error code used by `secupress_add_settings_error()`.
 *                      (string)      $type        `success` (default) or `error`. Will decide to send a success or an error message.
 **/
function secupress_admin_send_message_die( $args ) {
	$args = array_merge( array(
		'message'     => '',
		'redirect_to' => false,
		'code'        => '',
		'type'        => 'success',
	), $args );

	$is_ajax = defined( 'DOING_AJAX' ) && DOING_AJAX;

	if ( ! $args['message'] && ! $is_ajax ) {
		secupress_admin_die();
	}

	if ( $is_ajax ) {
		if ( 'success' === $args['type'] ) {
			unset( $args['redirect_to'], $args['type'] );
			wp_send_json_success( $args );
		}

		unset( $args['redirect_to'], $args['type'] );
		wp_send_json_error( $args );
	}

	if ( ! $args['redirect_to'] ) {
		$args['redirect_to'] = wp_get_referer();
	} elseif ( 0 !== strpos( $args['redirect_to'], 'http' ) ) {
		$args['redirect_to'] = secupress_admin_url( $args['redirect_to'] );
	}

	$args['type'] = 'success' === $args['type'] ? 'updated' : 'error';

	secupress_add_settings_error( 'general', $args['code'], $args['message'], $args['type'] );
	set_transient( 'settings_errors', secupress_get_settings_errors(), 30 );

	$goback = add_query_arg( 'settings-updated', 'true', $args['redirect_to'] );
	wp_redirect( esc_url_raw( $goback ) );
	die();
}


/**
 * A shorthand to test if the current user can perform SecuPress operations. Die otherwise.
 *
 * @since 1.0
 *
 * @param (bool) $force_mono Set to true to force the use of the capability/role for monosite.
 */
function secupress_check_user_capability( $force_mono = false ) {
	if ( ! current_user_can( secupress_get_capability( $force_mono ) ) ) {
		secupress_admin_die();
	}
}


/**
 * A `check_admin_referer()` that also works for ajax.
 *
 * @since 1.0
 *
 * @param (int|string) $action    Action nonce.
 * @param (string)     $query_arg Optional. Key to check for nonce in `$_REQUEST` (since 2.5).
 *                                Default '_wpnonce'.
 *
 * @return (false|int) No ajax:
 *                     False if the nonce is invalid, 1 if the nonce is valid and generated between 0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
 *                     Ajax:
 *                     Send a JSON response back to an Ajax request, indicating failure.
 */
function secupress_check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
	if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
		if ( false === check_ajax_referer( $action, $query_arg, false ) ) {
			wp_send_json_error();
		}
	} else {
		return check_admin_referer( $action, $query_arg );
	}
}

