<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad Old Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_Old_Files extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.2';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		global $_old_files;
		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );
		$this->title    = __( 'Check if your installation still contains old WordPress files.', 'secupress' );
		$this->more     = sprintf( __( 'Since WordPress 2.0, about %s files were deleted, let’s check if your website needs a clean up.', 'secupress' ), number_format_i18n( count( $_old_files ) ) );
		$this->more_fix = __( 'Delete all old files because your actual installation does not need it.', 'secupress' );
		// Add wp-config-sample.php into $_old_files.
		add_filter( 'secupress._old_files', function( $files ) { $files[] = 'wp-config-sample.php'; return $files; } );
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'Your installation is free of old files.', 'secupress' ),
			1   => __( 'All old files have been deleted.', 'secupress' ),
			// "bad"
			/** Translators: 1 is a number, 2 is a file name (or a list of file names). */
			200 => _n_noop( 'Your installation contains <strong>%1$d old file</strong>: %2$s.', 'Your installation contains <strong>%1$d old files</strong>: %2$s.', 'secupress' ),
			201 => _n_noop( 'The following file could not be deleted: %s.', 'The following files could not be deleted: %s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/article/97-legacy-files-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		global $_old_files;

		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		$bads = array();

		if ( empty( $_old_files ) || ! is_array( $_old_files ) ) {
			// Should not happen.
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		/**
		* Filter the old WP files to add more file (don’t remove!)
		*/
		$_old_files = apply_filters( 'secupress._old_files', $_old_files );

		if ( ! empty( $_old_files ) ) {
			foreach ( $_old_files as $file ) {
				if ( @file_exists( ABSPATH . $file ) ) {
					// "bad"
					$bads[] = sprintf( '<code>%s</code>', $file );
				}
			}
		}

		if ( $count = count( $bads ) ) {
			// "bad"
			$this->slice_and_dice( $bads, 10 );
			$this->add_message( 200, array( $count, $count, $bads ) );
		} else {
			// "good"
			$this->add_message( 0 );
		}

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.4.5
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		if ( $this->has_fix_action_part( 'fix' ) ) {
			$this->fix();
		}
		// "good"
		$this->add_fix_message( 1 );
		return parent::manual_fix();
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		global $_old_files;

		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );

		$not_deleted = [];
		/**
		* Filter the old WP files to add more file (don’t remove!)
		*/
		$_old_files  = apply_filters( 'secupress._old_files', $_old_files );
		$filesystem  = secupress_get_filesystem();
		foreach ( $_old_files as $file ) {
			if ( $filesystem->exists( ABSPATH . $file ) && ( ! wp_is_writable( ABSPATH . $file ) || ! $filesystem->delete( ABSPATH . $file ) ) ) {
				$not_deleted[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( $count = count( $not_deleted ) ) {
			// "bad"
			$this->slice_and_dice( $not_deleted, 10 );
			$this->add_fix_message( 201, array( $count, $count, $not_deleted ) );
		} else {
			// "good"
			$this->add_fix_message( 1 );
		}

		return parent::fix();
	}
}
