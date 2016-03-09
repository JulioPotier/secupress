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
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if your installation still contains old files from WordPress 2.0 to your current version.', 'secupress' );
		self::$more     = sprintf( __( 'Since WordPress 2.0, about %s files were deleted, let\'s check if your website needs a clean up.', 'secupress' ), number_format_i18n( 650 ) );
		self::$more_fix = __( 'The fix will delete all old files because your actual installation doesn\'t need it.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your installation is free of old files.', 'secupress' ),
			1   => __( 'All old files have been deleted.', 'secupress' ),
			// bad
			/* translators: 1 is a number, 2 is a file name (or a list of file names). */
			200 => _n_noop( 'Your installation contains <strong>%1$d old file</strong>: %2$s.', 'Your installation contains <strong>%1$d old files</strong>: %2$s.', 'secupress' ),
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

		$bads = array();

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
			$this->slice_and_dice( $bads, 10 );
			$this->add_message( 200, array( $count, $count, $bads ) );
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
			if ( @file_exists( ABSPATH . $file ) && ( ! is_writable( ABSPATH . $file ) || ! @unlink( ABSPATH . $file ) ) ) {
				$not_deleted[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( $count = count( $not_deleted ) ) {
			// bad
			$this->add_fix_message( 201, array( $count, $count, $not_deleted ) );
		} else {
			// good
			$this->add_fix_message( 1 );
		}

		return parent::fix();
	}
}
