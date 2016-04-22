<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

if ( ! function_exists( 'doing_filter' ) ) :
	/**
	 * Retrieve the name of a filter currently being processed.
	 *
	 * The function current_filter() only returns the most recent filter or action
	 * being executed. did_action() returns true once the action is initially
	 * processed.
	 *
	 * This function allows detection for any filter currently being
	 * executed (despite not being the most recent filter to fire, in the case of
	 * hooks called from hook callbacks) to be verified.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 *
	 * @see current_filter()
	 * @see did_action()
	 * @global array $wp_current_filter Current filter.
	 *
	 * @param (null|string) $filter Optional. Filter to check. Defaults to null, which
	 *                              checks if any filter is currently being run.
	 *
	 * @return (bool) Whether the filter is currently in the stack.
	 */
	function doing_filter( $filter = null ) {
		global $wp_current_filter;

		if ( null === $filter ) {
			return ! empty( $wp_current_filter );
		}

		return in_array( $filter, $wp_current_filter );
	}
endif;


if ( ! function_exists( 'doing_action' ) ) :
	/**
	 * Retrieve the name of an action currently being processed.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 *
	 * @param (string|null) $action Optional. Action to check. Defaults to null, which checks
	 *                            if any action is currently being run.
	 *
	 * @return (bool) Whether the action is currently in the stack.
	 */
	function doing_action( $action = null ) {
		return doing_filter( $action );
	}
endif;


if ( ! function_exists( 'wp_normalize_path' ) ) :
	/**
	 * Normalize a filesystem path.
	 *
	 * On windows systems, replaces backslashes with forward slashes and forces upper-case drive letters.
	 * Allows for two leading slashes for Windows network shares, but ensures that all other duplicate slashes are reduced to a single.
	 *
	 * @since 1.0
	 * @since WP 3.9.0
	 * @since WP 4.4.0 Ensures upper-case drive letters on Windows systems.
	 * @since WP 4.5.0 Allows for Windows network shares.
	 *
	 * @param (string) $path Path to normalize.
	 *
	 * @return (string) Normalized path.
	 */
	function wp_normalize_path( $path ) {
		$path = str_replace( '\\', '/', $path );
		$path = preg_replace( '|(?<=.)/+|', '/', $path );
		if ( ':' === substr( $path, 1, 1 ) ) {
			$path = ucfirst( $path );
		}
		return $path;
	}
endif;


/**
 * First half of escaping for LIKE special characters % and _ before preparing for MySQL.
 *
 * Use this only before wpdb::prepare() or esc_sql().  Reversing the order is very bad for security.
 *
 * Example Prepared Statement:
 *  $wild = '%';
 *  $find = 'only 43% of planets';
 *  $like = $wild . $wpdb->esc_like( $find ) . $wild;
 *  $sql  = $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE post_content LIKE %s", $like );
 *
 * Example Escape Chain:
 *  $sql  = esc_sql( $wpdb->esc_like( $input ) );
 *
 * @since 1.0
 * @since WP 4.0.0
 *
 * @param (string) $text The raw text to be escaped. The input typed by the user should have no extra or deleted slashes.

 * @return (string) Text in the form of a LIKE phrase. The output is not SQL safe. Call $wpdb::prepare() or real_escape next.
 */
function secupress_esc_like( $text ) {
	global $wpdb;

	if ( method_exists( $wpdb, 'esc_like' ) ) {
		return $wpdb->esc_like( $text );
	}

	return addcslashes( $text, '_%\\' );
}
