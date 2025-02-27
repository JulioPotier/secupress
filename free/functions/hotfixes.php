<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

remove_filter( 'wp_robots', 'wp_robots_noindex_embeds' );
remove_filter( 'wp_robots', 'wp_robots_noindex_search' );
add_action( 'wp', 'secupress_late_robots_check' );
/**
 * Load the robots condition tags later to prevent php warning
 *
 * @see https://core.trac.wordpress.org/ticket/53262
 * @author Julio Potier
 * @since 2.2
 * 
 * @return (void)
 **/
function secupress_late_robots_check() {
    add_filter( 'wp_robots', 'wp_robots_noindex_embeds' );
    add_filter( 'wp_robots', 'wp_robots_noindex_search' );
}

add_filter( 'doing_it_wrong_trigger_error', 'secupress_remove_fking_warning_from_wp67', 10, 2 );
/**
 * Prevent the useless message from the bug inserted in WP 6.7 by WP CORE DEVs, congratz to the test team.
 * ps: Works for all the plugins not only SecuPress.
 *
 * @see https://core.trac.wordpress.org/ticket/62462
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return (bool)
 **/
function secupress_remove_fking_warning_from_wp67( $bool, $function_name ) {
    if ( '_load_textdomain_just_in_time' === $function_name ) {
        $bool = false;
    }
    return $bool;
}