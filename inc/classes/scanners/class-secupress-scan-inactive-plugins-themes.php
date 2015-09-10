<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Inactive Plugins Themes scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Inactive_Plugins_Themes extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'inactive_plugins_themes';
	public    static $prio = 'medium';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if you got some deactivated plugins or themes.', 'secupress' );
		self::$more  = __( 'Even deactivated plugins or themes can potentially be exploited to some vulnerabilities.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t have any deactivated plugins or themes.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d deactivated plugin</strong>, if you don\'t need it, delete it: %s', '<b>%d deactivated plugins</b>, if you don\'t need them, delete them: %s', 'secupress' ),
			201 => _n_noop( '<strong>%d deactivated theme</strong>, if you don\'t need it, delete it: %s', '<b>%d deactivated themes</b>, if you don\'t need them, delete them: %s', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// Inactive plugins
		$plugins = get_plugins();
		$plugins = array_intersect_key( $plugins, array_flip( array_filter( array_keys( $plugins ), 'is_plugin_inactive' ) ) );

		if ( $count = count( $plugins ) ) {
			// bad
			$plugins = self::wrap_in_tag( wp_list_pluck( $plugins, 'Name' ) );
			$this->add_message( 200, array( $count, $count, wp_sprintf_l( '%l', $plugins ) ) );
		}

		// Inactive themes
		$themes = wp_get_themes();
		$themes = array_diff( wp_list_pluck( $themes, 'Name' ), array( $themes->Name ) );	//// Attention au thème parent si on utilise un thème enfant !

		if ( $count = count( $themes ) ) {
			// bad
			$themes = self::wrap_in_tag( $themes );
			$this->add_message( 201, array( $count, $count, wp_sprintf_l( '%l', $themes ) ) );
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
