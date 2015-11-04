<?php
/*
Module Name: Block Bad Url Length
Description: Block requests containing more than 300 (default) chars in URL
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

$parse_url = explode( '?', $_SERVER['REQUEST_URI'] );
$parse_url = parse_str( end( $parse_url ), $args );

unset( $args['_wp_http_referer'] );

$args = apply_filters( 'secupress.plugin.args.bad-url-length', $args );

$url_test = http_build_query( $args );

if ( strlen( $url_test ) > apply_filters( 'secupress.plugin.len.bad-url-length', 300 ) ) {
	secupress_block( 'BUL', 414 );
}

unset( $url_test, $args, $parse_url );