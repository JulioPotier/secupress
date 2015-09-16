<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Old Plugins scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Old_Plugins extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if you are using plugins that have been deleted from the official repository or not updated since two years at least.', 'secupress' );
		self::$more  = __( 'Avoid to use a plugin that have been removed from the official repository, and avoid using a plugin that have not been maintained for two years at least.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You don\'t use bad or old plugins.', 'secupress' ),
			// warning
			100 => __( 'Error, could not read %s.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d</strong> plugin is <strong>no longer</strong> in the WordPress directory: %s.', '<strong>%d</strong> plugins are <strong>no longer</strong> in the WordPress directory: %s.', 'secupress' ),
			201 => _n_noop( '<strong>%d</strong> plugin hasn\'t been updated <strong>for 2 years</strong> at least: %s.', '<strong>%d</strong> plugins haven\'t been updated <strong>for 2 years</strong> at least: %s.', 'secupress' ),
			202 => __( 'You should delete the plugin %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		// Plugins no longer in directory - http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/
		$plugins_list_file = SECUPRESS_INC_PATH . 'data/no-longer-in-directory-plugin-list.txt';
		$plugins           = get_plugins();

		if ( is_readable( $plugins_list_file ) ) {

			$not_in_directory = array_flip( array_map( 'chop', file( $plugins_list_file ) ) );
			$all_plugins      = array_combine( array_map( 'dirname', array_keys( $plugins ) ), $plugins );
			$bad_plugins      = array_intersect_key( $all_plugins, $not_in_directory );

			if ( $count = count( $bad_plugins ) ) {
				// bad
				$bad_plugins = wp_list_pluck( $bad_plugins, 'Name' );
				$bad_plugins = self::wrap_in_tag( $bad_plugins );
				$bad_plugins = wp_sprintf_l( '%l', $bad_plugins );

				$this->add_message( 200, array( $count, $count, $bad_plugins ) );
			}

		} else {
			// warning
			$this->add_message( 100, array( '<code>' . str_replace( ABSPATH, '', $plugins_list_file ) . '</code>' ) );
		}

		// Plugins not updated in over 2 years - http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/
		$plugins_list_file = SECUPRESS_INC_PATH . 'data/not-updated-in-over-two-years-plugin-list.txt';

		if ( is_readable( $plugins_list_file ) ) {

			$not_updated = array_flip( array_map( 'chop', file( $plugins_list_file ) ) );
			$all_plugins = array_combine( array_map( 'dirname', array_keys( $plugins ) ), $plugins );
			$bad_plugins = array_intersect_key( $all_plugins, $not_updated );

			if ( $count = count( $bad_plugins ) ) {
				// bad
				$bad_plugins = wp_list_pluck( $bad_plugins, 'Name' );
				$bad_plugins = self::wrap_in_tag( $bad_plugins );
				$bad_plugins = wp_sprintf_l( '%l', $bad_plugins );

				$this->add_message( 201, array( $count, $count, $bad_plugins ) );
			}

		} else {
			// warning
			$this->add_message( 100, array( '<code>' . str_replace( ABSPATH, '', $plugins_list_file ) . '</code>' ) );

		}

		// Check for Hello Dolly existence.
		if ( file_exists( WP_PLUGIN_DIR . '/hello.php' ) ) {
			// bad
			$this->add_message( 202, array( '<strong>Hello Dolly</strong>' ) );
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
