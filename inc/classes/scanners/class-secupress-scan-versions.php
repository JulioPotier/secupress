<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Versions scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Versions extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'versions';
	public    static $prio = 'high';


	public function __construct() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress core, plugins, and themes are up to date.', 'secupress' );
		self::$more  = __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You are totally up to date, WordPress, plugins and themes. Bravo.', 'secupress' ),
			// bad
			200 => __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a plugin or theme, contact its author and submit him your issue.', 'secupress' ),
			201 => __( 'WordPress <strong>core</strong> is not up to date.', 'secupress' ),
			202 => _n_noop( '<strong>%1$d</strong> plugin isn\'t up to date: %2$s.', '<strong>%1$d</strong> plugins aren\'t up to date: %2$s.', 'secupress' ),
			203 => _n_noop( '<strong>%1$d</strong> theme isn\'t up to date: %2$s.',  '<strong>%1$d</strong> themes aren\'t up to date: %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to manually update your plugins, themes and WordPress core.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// Core
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/update.php' );
		}

		wp_version_check();
		$core_update = get_preferred_from_update_core();
		$core_update = isset( $core_update->response ) && 'upgrade' === $core_update->response;

		// Plugins
		$current        = get_site_transient( 'update_plugins' );
		$plugin_updates = array();

		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$plugin_updates = wp_list_pluck( array_intersect_key( get_plugins(), array_flip( array_keys( $current->response ) ) ), 'Name' );
		}

		// Themes
		$current       = get_site_transient( 'update_themes' );
		$theme_updates = array();

		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$theme_updates = wp_list_pluck( array_map( 'wp_get_theme', array_keys( $current->response ) ), 'Name' );
		}

		if ( $core_update || $plugin_updates || $theme_updates ) {

			// bad
			$this->add_message( 200 );

			if ( $core_update ) {
				$this->add_message( 201 );
			}

			if ( $count = count( $plugin_updates ) ) {
				$this->add_message( 202, array( $count, $count, wp_sprintf_l( '%l', self::wrap_in_tag( $plugin_updates ) ) ) );
			}

			if ( $count = count( $theme_updates ) ) {
				$this->add_message( 203, array( $count, $count, wp_sprintf_l( '%l', self::wrap_in_tag( $theme_updates ) ) ) );
			}
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
