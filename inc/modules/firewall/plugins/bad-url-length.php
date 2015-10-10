<?php
/*
Module Name: Block Bad Url Length
Description: Block requests containing more than 255 chars in URL
Main Module: firewall
Author: SecuPress
Version: 1.0
*/

if ( strlen( $_SERVER['REQUEST_URI'] ) > 255 ) {
	secupress_block( 'BUL', 414 );
}