<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * "Active plugins and themes option" first filling background process class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Admin_APTO_First_Filling_Process extends WP_Background_Process {

	/**
	 * @var string
	 */
	protected $action = 'apto_process';
	/**
	 * Task.
	 * Performs actions required on each queue item. Returns the modified item for further processing in the next pass through. Or, returns false to remove the item from the queue.
	 *
	 * @param (mixed) $item Queue item to iterate over.
	 *
	 * @return (mixed)
	 */
	protected function task( $item ) {
		global $wpdb;

		$blog_id      = (int) $item;
		$table_prefix = $wpdb->get_blog_prefix( $blog_id );
		$blog_actives = $wpdb->get_results( "SELECT option_name, option_value FROM {$table_prefix}options WHERE option_name = 'active_plugins' OR option_name = 'stylesheet'", OBJECT_K );

		// Plugins
		$plugins = get_site_option( 'secupress_active_plugins' );
		$plugins = is_array( $plugins ) ? $plugins : array();

		$plugins[ $blog_id ] = ! empty( $blog_actives['active_plugins']->option_value ) ? unserialize( $blog_actives['active_plugins']->option_value ) : array();

		if ( $plugins[ $blog_id ] && is_array( $plugins[ $blog_id ] ) ) {
			$plugins[ $blog_id ] = array_fill_keys( $plugins[ $blog_id ], 1 );
		}

		update_site_option( 'secupress_active_plugins', $plugins );

		// Themes
		$themes  = get_site_option( 'secupress_active_themes' );
		$themes  = is_array( $themes )  ? $themes  : array();

		$themes[ $blog_id ] = ! empty( $blog_actives['stylesheet']->option_value ) ? $blog_actives['stylesheet']->option_value : '';

		update_site_option( 'secupress_active_themes', $themes );

		return false;
	}
}
