<?php
/*
Module Name: Block Bad Request Methods
Description: Block requests methods spotted as potentially dangerous
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

// Block Bad request methods
if ( ! in_array( $_SERVER['REQUEST_METHOD'], array( 'GET', 'POST', 'HEAD' ) ) ) {
	secupress_block( 'RMHM', 405 );
}

// Block Bad protocol method
if ( 'POST' === $_SERVER['REQUEST_METHOD'] && ! isset( $_SERVER['SERVER_PROTOCOL'] ) || 'HTTP/1.1' !== $_SERVER['SERVER_PROTOCOL'] ) {
	secupress_block( 'RMHP', 505 );
}


// Block Bad post with referer request
if ( 'POST' === $_SERVER['REQUEST_METHOD'] && ( ! isset( $_SERVER['HTTP_REFERER'] ) || '' === trim( $_SERVER['HTTP_REFERER'] ) ) ) {
	secupress_block( 'RMHR', 400 );
}