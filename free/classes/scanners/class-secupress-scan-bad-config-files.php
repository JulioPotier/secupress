<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad Config Files scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_Config_Files extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		$this->title    = sprintf( __( 'Check if your installation contains backed up %1$s files like %2$s.', 'secupress' ), secupress_code_me( 'wp-config.php' ), secupress_code_me( 'wp-config.bak/.old' ) );
		$this->more     = __( 'Some attackers will try to find some backed up config files to try to steal them. Prevent this kind of attack simply by removing them.', 'secupress' );
		$this->more_fix = sprintf( __( 'Rename all the %1$s files using a random name and still using the %2$s extension to prevent being downloaded.', 'secupress' ), secupress_code_me( 'wp-config.bak/.old' ), secupress_code_me( '.php' ) );
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
			0   => sprintf( __( 'You don’t have backed up %s files.', 'secupress' ), secupress_code_me( 'wp-config' ) ),
			1   => sprintf( __( 'Your backed up %1$s file was successfully suffixed with %2$s.', 'secupress' ), secupress_code_me( 'wp-config.php' ), '%s' ),
			// "warning"
			100 => sprintf( __( '%1$d backed up %3$s file was successfully suffixed with %2$s.', 'secupress' ), '%1$d', '%2$s', secupress_code_me( 'wp-config.php' ) ),
			101 => _n_noop( 'Sorry, this file could not be renamed: %s', 'Sorry, those files could not be renamed: %s', 'secupress' ),
			// "bad"
			200 => sprintf( __( 'Your installation should not contain this backed up %1$s file: %2$s.', 'secupress' ), secupress_code_me( 'wp-config.php' ), '%s' ),
			201 => sprintf( __( 'Sorry, the backed up %s file could not be renamed.', 'secupress' ), secupress_code_me( 'wp-config.php' ) ),
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
		return __( 'https://docs.secupress.me/article/96-wp-config-php-file-backups-scan', 'secupress' );
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

		$files = static::get_files();

		if ( $files ) {
			// "bad"
			$files = self::wrap_in_tag( $files );
			$this->add_message( 200, array( count( $files ), $files ) );
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
		$this->add_fix_message( 1, __( 'a safe file extension', 'secupress' ) );
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
		$files = static::get_files();

		// Should not happen.
		if ( ! $files ) {
			// "good"
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		$wp_filesystem = secupress_get_filesystem();
		$count_all     = count( $files );
		$renamed       = array();
		$suffix        = '.' . time() . '.secupress.php';

		// Rename the files.
		foreach ( $files as $filename ) {
			$new_file = ABSPATH . $filename . $suffix;

			if ( $wp_filesystem->move( ABSPATH . $filename, $new_file ) ) {
				$wp_filesystem->chmod( $new_file, FS_CHMOD_FILE );
				// Counting the renamed files is safer that counting the not renamed ones.
				$renamed[] = $filename;
			}
		}

		$count_renamed = count( $renamed );

		if ( $count_renamed === $count_all ) {
			// "good": all files were renamed.
			$this->add_fix_message( 1, array( $count_all, '<code>' . $suffix . '</code>' ) );
		} elseif ( $count_renamed ) {
			// "warning": some files could not be renamed.
			$not_renamed = array_diff( $files, $renamed );
			$not_renamed = static::wrap_in_tag( $not_renamed );

			$this->add_fix_message( 100, array( $count_renamed, $count_renamed, '<code>' . $suffix . '</code>' ) );
			$this->add_fix_message( 101, array( count( $not_renamed ), $not_renamed ) );
		}
		else {
			// "bad": no files could not be renamed.
			$this->add_fix_message( 201, array( $count_all ) );
		}

		return parent::fix();
	}


	/** Tools. ================================================================================== */

	/**
	 * Get config files.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of file names.
	 */
	protected static function get_files() {
		$files = glob( ABSPATH . '*wp-config*.*' );
		$files = array_map( 'basename', $files );

		foreach ( $files as $k => $file ) {
			if ( 'php' === pathinfo( $file, PATHINFO_EXTENSION ) ) {
				unset( $files[ $k ] );
			}
		}

		return $files;
	}
}
