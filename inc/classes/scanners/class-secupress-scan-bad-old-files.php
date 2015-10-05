<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Old Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Old_Files extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your installation still contains old files from WordPress 2.0 to your current version.', 'secupress' );
		self::$more  = sprintf( __( 'Since WordPress 2.0, about %s files were deleted, let\'s check if you need a clean up.', 'secupress' ), number_format_i18n( 650 ) );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your installation is free of old files.', 'secupress' ),
			1   => __( 'All old files were deleted.', 'secupress' ),
			// bad
			200 => _n_noop( 'Your installation contains %1$d old file: %2$s.', 'Your installation contains old files: %2$s.', 'secupress' ),
			201 => _n_noop( 'The following file could not be deleted: %s.', 'The following files could not be deleted: %s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $_old_files;

		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		$not_deleted = array();

		if ( empty( $_old_files ) || ! is_array( $_old_files ) ) {
			// Should not happen.
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		foreach ( $_old_files as $file ) {
			if ( @file_exists( ABSPATH . $file ) ) {
				// bad
				$bads[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( $count = count( $bads ) ) {
			// bad
			$this->add_message( 200, array( $count, $count, wp_sprintf_l( '%l', $bads ) ) );
		} else {
			// good
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	public function fix() {
		global $_old_files;

		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		$not_deleted = array();

		if ( empty( $_old_files ) || ! is_array( $_old_files ) ) {
			// Should not happen.
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		foreach ( $_old_files as $file ) {
			if ( @file_exists( ABSPATH . $file ) && ! is_writable( ABSPATH . $filename ) || ! @unlink( ABSPATH . $filename ) ) {
				$not_deleted[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( $count = count( $not_deleted ) ) {
			// bad
			$this->add_fix_message( 201, array( $count, $count, wp_sprintf_l( '%l', $not_deleted ) ) );
		} else {
			// good
			$this->add_fix_message( 1 );
		}

		return parent::fix();
	}
}
