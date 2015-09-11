<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Old Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Old_Files extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'bad_old_files';
	public    static $prio = 'high';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your installation still contains old files from WordPress 2.0 to your version.', 'secupress' );
		self::$more  = __( 'Since WordPress 2.0, about 500 files were deleted, let\'s check if you need a clean up.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your installation is free of old files.', 'secupress' ),
			// bad
			200 => __( 'Your installation contains old files: %s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $_old_files;

		$bads = array();

		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		if ( ! empty( $_old_files ) && is_array( $_old_files ) ) {
			foreach ( $_old_files as $file ) {
				if ( @file_exists( ABSPATH . $file ) ) {
					// bad
					$bads[] = sprintf( '<code>%s</code>', $file );
				}
			}
		}

		if ( $bads ) {
			// bad
			$this->add_message( 200, array( wp_sprintf_l( '%l', $bads ) ) );
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
