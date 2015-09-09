<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Versions scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Versions extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'versions';
	public    static $prio = 'high';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress core, plugins, and themes are up to date.', 'secupress' );
		self::$more  = __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress' );
	}


	public static function get_messages( $id = null ) {
		// Hint: when retrieving messages, test with `is_array()` to detect `_n_noop()`.
		$messages = array(
				// good
				0 => __( 'You are totally up to date, WordPress, plugins and themes. Bravo.', 'secupress' ),
				// warning
				100 => __( 'Impossible to determine the updateness of your installation.', 'secupress' ),
				// bad
				200 => __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress' ),
				201 => __( 'WordPress <strong>core</strong> is not up to date.', 'secupress' ),
				202 => _n_noop( '<b>%1$d</b> plugin isn\'t up to date: <code>%2$s</code>.', '<b>%1$d</b> plugins aren\'t up to date: <code>%2$s</code>.', 'secupress' ),
				203 => _n_noop( '<b>%1$d</b> theme isn\'t up to date: <code>%2$s</code>', '<b>%1$d</b> themes aren\'t up to date: <code>%2$s</code>', 'secupress' ),
				204 => __( 'Your server is running on <code>PHP v%1$s</code>, it\'s an outdated version, use <code>v%2$s</code> at least.', 'secupress' ),
				// cantfix
				300 => __( 'I can not fix this, you have to manually update your plugins, themes and WordPress core.', 'secupress' ),
			);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// Core
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/update.php' );
		}

		wp_version_check();
		$latest_core_update = get_preferred_from_update_core();

		// Plugins
		$current = get_site_transient( 'update_plugins' );

		if ( ! is_object( $current ) ) {
			$current = new stdClass;
		}

		$current = get_site_transient( 'update_plugins' );

		$plugin_updates = array();
		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$plugin_updates = wp_list_pluck( array_intersect_key( get_plugins(), array_flip( array_keys( $current->response ) ) ), 'Name' );
		}

		// Themes
		$current = get_site_transient( 'update_themes' );

		if ( ! is_object( $current ) ) {
			$current = new stdClass;
		}

		$current = get_site_transient( 'update_themes' );

		$theme_updates = array();
		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$theme_updates = wp_list_pluck( array_map( 'wp_get_theme', array_keys( $current->response ) ), 'Name' );
		}

		if ( isset( $latest_core_update->response ) && ( $latest_core_update->response == 'upgrade' ) ||
			$plugin_updates || $theme_updates
		) {
			$this->add_message( 200 );
			if ( isset( $latest_core_update->response ) && ( 'upgrade' == $latest_core_update->response ) ) {
				$this->add_message( 201 );
			}
			if ( count( $plugin_updates ) ) {
				$this->add_message( 202, array( count( $plugin_updates ), count( $plugin_updates ), implode( '</code>, <code>', $plugin_updates ) ) );
			}
			if ( count( $theme_updates ) ) {
				$this->add_message( 203, array( count( $theme_updates ), count( $theme_updates ), implode( '</code>, <code>', $theme_updates ) ) );
			}
		}

		return parent::scan();
	}


    public function fix() {

        // include the fix here.

        return parent::fix();
    }
}
