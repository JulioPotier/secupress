<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

add_filter( 'http_request_args', '__secupress_add_own_ua', 10, 3 );
/**
 * Force our user agent header when we hit our urls
 *
 * @since 1.0
 *
 * @param (array)  $r   The request parameters.
 * @param (string) $url The request URL.
 *
 * @return (array)
 */
function __secupress_add_own_ua( $r, $url ) {
	if ( false !== strpos( $url, 'secupress.me' ) ) {
		$r['headers']['x-secupress'] = secupress_user_agent( $r['user-agent'] );
	}

	return $r;
}
