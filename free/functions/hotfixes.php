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
 * @return (void)
 **/
function secupress_late_robots_check() {
    add_filter( 'wp_robots', 'wp_robots_noindex_embeds' );
    add_filter( 'wp_robots', 'wp_robots_noindex_search' );
}
/** **/