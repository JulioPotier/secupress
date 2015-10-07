<?php
/*
Module Name: Generator disclose
Description: Remove the generator meta tag.
Main Module: discloses
Author: SecuPress
Version: 1.0
*/
defined( 'SECUPRESS_VERSION' ) or die( 'Cheatin&#8217; uh?' );


// Remove the meta tag.

foreach ( array( 'wp_head', 'rss2_head', 'commentsrss2_head', 'rss_head', 'rdf_header', 'atom_head', 'comments_atom_head', 'opml_head', 'app_head' ) as $action ) {
	remove_action( $action, 'the_generator' );
}


// Just to be sure, bloat its value: some plugin/theme may add the tag back.

add_filter( 'the_generator', '__return_empty_string', PHP_INT_MAX );
