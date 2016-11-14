<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Chmods scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Chmods extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0';


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
		$this->title    = __( 'Check if your files and folders have the correct write permissions (chmod).', 'secupress' );
		$this->more     = __( 'CHMOD is the way to give read/write/execute rights to a file or a folder. The <code>0777</code> value is bad and should be avoided. This test will check some strategic files and folders.', 'secupress' );
		$this->more_fix = __( 'Change the files permissions to the recommended one for each.', 'secupress' );
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
			0   => __( 'All file permissions are good.', 'secupress' ),
			1   => __( 'All file permissions are fixed.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine the file permissions of %s.', 'secupress' ),
			// "bad"
			200 => _x( 'File permissions for %1$s <strong>should be %2$s</strong>, NOT %3$s!', '1: file path, 2: chmod required, 3: current chmod', 'secupress' ),
			201 => __( 'Unable to apply new file permissions to %s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
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
		$warnings = array();
		$files    = static::get_file_perms();
		$abspath  = realpath( ABSPATH );

		clearstatcache();

		foreach ( $files as $file => $chmod ) {
			// Current file perm.
			$current = (int) decoct( fileperms( $file ) & 0777 );
			$file    = ltrim( str_replace( $abspath, '', realpath( $file ) ), '\\' );
			$file    = '' === $file ? '/' : $file;

			if ( ! $current ) {
				// "warning": unable to determine file perm.
				$warnings[] = sprintf( '<code>%s</code>', $file );

			} elseif ( $current > $chmod ) {
				// "bad"
				$this->add_message( 200, array(
					sprintf( '<code>%s</code>', $file ),
					sprintf( '<code>0%s</code>', $chmod ),
					sprintf( '<code>0%s</code>', $current ),
				) );
			}
		}

		if ( $warnings ) {
			// "warning"
			$this->add_message( 100, array( $warnings ) );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		$warnings  = array();
		$bads      = array();
		$files     = static::get_file_perms();
		$files_tmp = array();
		$abspath   = realpath( ABSPATH );

		clearstatcache();

		foreach ( $files as $file => $chmod ) {
			// Current file perm.
			$current = (int) decoct( fileperms( $file ) & 0777 );

			if ( ! $current || $current > $chmod ) {
				// Apply new file perm.
				@chmod( $file, octdec( $chmod ) );
				$files_tmp[ $file ] = $chmod;
			}
		}

		$count = count( $files_tmp );
		clearstatcache();

		foreach ( $files_tmp as $file => $chmod ) {
			// Check if it worked.
			$current = (int) decoct( fileperms( $file ) & 0777 );
			$file    = ltrim( str_replace( $abspath, '', realpath( $file ) ), '\\' );
			$file    = '' === $file ? '/' : $file;

			if ( ! $current ) {
				// "warning": unable to determine file perm.
				$warnings[] = sprintf( '<code>%s</code>', $file );
			} elseif ( $current > $chmod ) {
				// "bad": unable to apply the file perm.
				$bads[] = sprintf( '<code>%s</code>', $file );
			}
		}

		if ( ! $count ) {
			// "good" (there was nothing to fix).
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		if ( $bads ) {
			// "bad"
			$this->add_fix_message( 201, array( $bads ) );
		}

		if ( $warnings ) {
			// "warning"
			$this->add_fix_message( 100, array( $warnings ) );
		}

		// "good"
		$this->maybe_set_fix_status( 1 );

		return parent::fix();
	}


	/** Tools. ================================================================================== */

	/**
	 * Get chmod values that some directories or files that should be set to.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of path => chmod.
	 */
	protected static function get_file_perms() {
		global $is_apache;

		$_wp_upload_dir = wp_upload_dir();
		$files          = array(
			secupress_find_wpconfig_path()    => 644,
			ABSPATH                           => 755,
			ABSPATH . 'wp-admin/'             => 755,
			ABSPATH . WPINC . '/'             => 755,
			WP_CONTENT_DIR . '/'              => 755,
			get_theme_root() . '/'            => 755,
			plugin_dir_path( SECUPRESS_FILE ) => 755,
			$_wp_upload_dir['basedir'] . '/'  => 755,
		);

		if ( $is_apache ) {
			$files[ ABSPATH . '.htaccess' ] = 644;
		}

		return $files;
	}
}
