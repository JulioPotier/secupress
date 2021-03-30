<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Chmods scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Chmods extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/**
	 * Reminder:
	 *
	 * `$perm = fileperms( $file );`
	 *
	 *  WHAT                                         | TYPE   | FILE   | FOLDER |
	 * ----------------------------------------------+--------+--------+--------|
	 * `$perm`                                       | int    | 33188  | 16877  |
	 * `substr( decoct( $perm ), -4 )`               | string | '0644' | '0755' |
	 * `substr( sprintf( '%o', $perm ), -4 )`        | string | '0644' | '0755' |
	 * `$perm & 0777`                                | int    | 420    | 493    |
	 * `decoct( $perm & 0777 )`                      | string | '644'  | '755'  |
	 * `substr( sprintf( '%o', $perm & 0777 ), -4 )` | string | '644'  | '755'  |
	 */

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '2.0';


	/** Properties. ============================================================================= */

	/**
	 * Targeted chmod for folders.
	 *
	 * @var (int) Integer value of 0755.
	 */
	protected $folder_chmod = 493;

	/**
	 * Targeted chmod for files.
	 *
	 * @var (int) Integer value of 0644.
	 */
	protected $file_chmod = 420;

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
		$this->more     = __( 'CHMOD is the way to give read/write/execute rights to a file or a folder. This test will check some strategic files and folders.', 'secupress' );
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
			202 => _nx_noop(
				'File permissions for the following folder <strong>should be %1$s</strong>: %2$s.',
				'File permissions for the following folders <strong>should be %1$s</strong>: %2$s.',
				'1: chmod required, 2: folder path(s)',
				'secupress'
			),
			203 => _nx_noop(
				'File permissions for the following file <strong>should be %1$s</strong>: %2$s.',
				'File permissions for the following files <strong>should be %1$s</strong>: %2$s.',
				'1: chmod required, 2: folder path(s)',
				'secupress'
			),
			204 => _n_noop(
				'Unable to apply new permissions to the file or folder %s.',
				'Unable to apply new permissions to the files or folders %s.',
				'secupress'
			),
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
		return __( 'https://docs.secupress.me/article/125-file-permission-scan', 'secupress' );
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

		$warnings = array();
		$folders  = array();
		$files    = array();
		$to_test  = $this->get_files();
		$abspath  = realpath( ABSPATH );

		clearstatcache();

		// Folders.
		foreach ( $to_test['folders'] as $file_path ) {
			// Current folder perm.
			$file_path     = realpath( $file_path );
			$current_chmod = fileperms( $file_path ) & 0777;
			$file_relative = ltrim( str_replace( $abspath, '', $file_path ), '\\' );
			$file_relative = '' === $file_relative ? '/' : $file_relative;

			if ( ! $current_chmod ) {
				// "warning": unable to determine folder perm.
				$warnings[] = sprintf( '<code>%s</code>', $file_relative );

			} elseif ( $current_chmod > $this->folder_chmod ) {
				// "bad".
				$folders[] = sprintf( '<code>%s</code> (<code>%s</code>)', $file_relative, static::to_octal( $current_chmod ) );
			}
		}

		// Files.
		if ( $to_test['files'] ) {
			foreach ( $to_test['files'] as $file_path ) {
				// Current file perm.
				$file_path     = realpath( $file_path );
				$current_chmod = fileperms( $file_path ) & 0777;
				$file_relative = ltrim( str_replace( $abspath, '', $file_path ), '\\' );
				$file_relative = '' === $file_relative ? '/' : $file_relative;

				if ( ! $current_chmod ) {
					// "warning": unable to determine file perm.
					$warnings[] = sprintf( '<code>%s</code>', $file_relative );

				} elseif ( $current_chmod > $this->file_chmod ) {
					// "bad".
					$files[] = sprintf( '<code>%s</code> (<code>%s</code>)', $file_relative, static::to_octal( $current_chmod ) );
				}
			}
		}

		if ( ! empty( $folders ) ) {
			// "bad"
			$this->add_message( 202, array( count( $folders ), sprintf( '<code>%s</code>', static::to_octal( $this->folder_chmod ) ), $folders ) );
		}

		if ( ! empty( $files ) ) {
			// "bad"
			$this->add_message( 203, array( count( $files ), sprintf( '<code>%s</code>', static::to_octal( $this->file_chmod ) ), $files ) );
		}

		if ( ! empty( $warnings ) ) {
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
		$warnings   = array();
		$files      = array();
		$failed     = array();
		$to_test    = $this->get_files();
		$abspath    = realpath( ABSPATH );
		$filesystem = secupress_get_filesystem();

		clearstatcache();

		// Folders.
		foreach ( $to_test['folders'] as $file_path ) {
			// Current folder perm.
			$current_chmod = fileperms( $file_path ) & 0777;

			if ( ! $current_chmod || $current_chmod > $this->folder_chmod ) {
				// Apply new folder perm.
				$filesystem->chmod( $file_path, $this->folder_chmod );
				$files[ $file_path ] = $this->folder_chmod;
			}
		}

		// Files.
		if ( $to_test['files'] ) {
			foreach ( $to_test['files'] as $file_path ) {
				// Current file perm.
				$current_chmod = @fileperms( $file_path ) & 0777;

				if ( ! $current_chmod || $current_chmod > $this->file_chmod ) {
					// Apply new file perm.
					@$filesystem->chmod( $file_path, $this->file_chmod );
					$files[ $file_path ] = $this->file_chmod;
				}
			}
		}

		// Check if it worked.
		clearstatcache();

		// Activate.
		secupress_activate_submodule( 'wordpress-core', 'wp-config-constant-fs-chmod' );

		if ( ! $files ) {
			// "good" (there was nothing to fix).
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		if ( $files ) {
			foreach ( $files as $file_path => $target_chmod ) {
				// Current file perm.
				$file_path     = realpath( $file_path );
				$current_chmod = fileperms( $file_path ) & 0777;
				$file_relative = ltrim( str_replace( $abspath, '', $file_path ), '\\' );
				$file_relative = '' === $file_relative ? '/' : $file_relative;

				if ( ! $current_chmod ) {
					// "warning": unable to determine file perm.
					$warnings[] = sprintf( '<code>%s</code>', $file_relative );

				} elseif ( $current_chmod > $target_chmod ) {
					// "bad": unable to apply the file perm.
					$failed[] = sprintf( '<code>%s</code> (<code>%s</code>)', $file_relative, static::to_octal( $target_chmod ) );
				}
			}
		}

		if ( $failed ) {
			// "bad"
			$this->add_fix_message( 204, array( count( $failed ), $failed ) );
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
	 * Get files and folders to test, categorized by type.
	 *
	 * @since 2.0 remove web.config+ better .htaccess path
	 * @since 1.2.2
	 *
	 * @return (array) An array of arrays of paths.
	 */
	protected function get_files() {
		$upload_dir        = wp_upload_dir();

		$files = array(
			'folders' => array(
				ABSPATH,
				ABSPATH . 'wp-admin',
				ABSPATH . WPINC,
				WP_CONTENT_DIR,
				get_theme_root(),
				WP_PLUGIN_DIR,
				$upload_dir['basedir'],
			),
			'files' => array(),
		);

		if ( file_exists( WPMU_PLUGIN_DIR ) ) {
			$files['folders'][] = WPMU_PLUGIN_DIR;
		}

		$files['folders'] = array_map( 'trailingslashit', $files['folders'] );

		$wpconfig_filepath = secupress_find_wpconfig_path();
		if ( file_exists( $wpconfig_filepath ) ) {
			$files['files'][] = $wpconfig_filepath;
		}

		$htaccess_path = trailingslashit( secupress_get_home_path() );
		$htaccess_file = $htaccess_path . '.htaccess';
		if ( file_exists( $htaccess_file ) ) {
			$files['files'][] = $htaccess_file;
		}

		return $files;
	}


	/**
	 * Transform an "octal" integer to a "readable" string like "0644".
	 *
	 * @since 1.2.2
	 *
	 * @param (int) $int An "octal" integer.
	 *
	 * @return (string).
	 */
	protected static function to_octal( $int ) {
		return substr( '0' . decoct( $int ), -4 );
	}
}
