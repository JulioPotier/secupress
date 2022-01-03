<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad File Extensions scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_File_Extensions extends SecuPress_Scan implements SecuPress_Scan_Interface {

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

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = 'pro';

	/**
	 * The test file path.
	 *
	 * @var (bool|string)
	 */
	protected $file_path = false;

	/**
	 * The test file URL.
	 *
	 * @var (bool|string)
	 */
	protected $file_url = false;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		global $is_apache, $is_nginx, $is_iis7;

		$this->title    = __( 'Check if there are files using bad extensions are accessible in the uploads folder.', 'secupress' );
		$this->more     = __( 'The uploads folder should only contain files like images, pdf, or zip archives. Other files should not be accessible by their URL.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Bad File Extensions', 'secupress' ) . '</strong>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'file-system' ) ) . '#module-bad-file-extensions">' . __( 'Malware Scan', 'secupress' ) . '</a>'
		);

		if ( ! $is_apache && ! $is_nginx && ! $is_iis7 ) {
			$this->more_fix = static::get_messages( 301 );
			$this->fixable  = false;
			return;
		}
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
		global $is_apache;

		$config_file = $is_apache ? '.htaccess' : 'web.config';
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Bad File Extensions', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'file-system' ) ) . '#module-bad-file-extensions">' . __( 'Malware Scan', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			0   => __( 'Files that use bad extensions are protected.', 'secupress' ),
			/** Translators: %s is a file name. */
			1   => sprintf( __( 'The rules forbidding access to files that use bad extensions have been successfully added to your %s file.', 'secupress' ), "<code>$config_file</code>" ),
			// "warning"
			100 => __( 'Unable to determine the status of the bad file extensions test file.', 'secupress' ) . ' ' . $activate_protection_message,
			// "bad"
			200 => __( 'Could not create a bad extension test file in the uploads folder.', 'secupress' ) . ' ' . $activate_protection_message,
			201 => __( 'Whether or not you have files using bad extensions in the uploads folder, those files are accessible directly.', 'secupress' ),
			// "cantfix"
			/** Translators: 1 is a file name, 2 is some code. */
			300 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the files that use bad extensions cannot be protected automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs an unrecognized system. The files that use bad extensions cannot be protected automatically.', 'secupress' ),
			/** Translators: 1 is a file name, 2 is some code. */
			302 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ), "<code>$config_file</code>", '%s' ),
			/** Translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code. */
			303 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ), "<code>$config_file</code>", '%1$s', '%2$s' ),
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
		return __( 'https://docs.secupress.me/article/124-bad-file-extension-scan', 'secupress' );
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

		// Create the temporary file.
		$this->create_file();

		if ( ! $this->file_url ) {
			// "bad"
			$this->add_message( 200 );
			return parent::scan();
		}

		$response = wp_remote_get( $this->file_url, $this->get_default_request_args() );

		if ( is_wp_error( $response ) ) {
			// "good"
			$this->add_message( 0 );

		} elseif ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			// "bad"
			$this->add_message( 201 );
		}

		// Delete the temporary file.
		$this->delete_file();

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
		global $is_apache, $is_nginx, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		} elseif ( $is_nginx ) {
			$this->fix_nginx();
		} else {
			$this->add_fix_message( 301 );
		}

		return parent::fix();
	}


	/**
	 * Fix for Apache system.
	 *
	 * @since 1.0
	 */
	protected function fix_apache() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			// "cantfix"
			$this->add_fix_message( 302, array( $rules ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1 );
	}


	/**
	 * Fix for IIS7 system.
	 *
	 * @since 1.0
	 */
	protected function fix_iis7() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			$path  = static::get_code_tag_from_error( $last_error, 'secupress-iis7-path' );
			// "cantfix"
			$this->add_fix_message( 303, array( $path, $rules ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1 );
	}


	/**
	 * Fix for nginx system.
	 *
	 * @since 1.0
	 */
	protected function fix_nginx() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Get the error.
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
		$rules      = '<code>Error</code>';

		if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			array_pop( $wp_settings_errors );
		}

		// "cantfix"
		$this->add_fix_message( 300, array( $rules ) );
	}


	/** Tools. ================================================================================== */

	/**
	 * Create a test file in the uploads folder. Also set the test file path and URL.
	 *
	 * @since 1.0
	 */
	protected function create_file() {
		$wp_filesystem = secupress_get_filesystem();
		$uploads       = wp_upload_dir( null, false );
		$basedir       = wp_normalize_path( $uploads['basedir'] );
		$extensions    = secupress_bad_file_extensions_get_forbidden_extensions();

		// Get the file name.
		$file_ext  = mt_rand( 0, count( $extensions ) - 1 );
		$file_ext  = $extensions[ $file_ext ];
		$file_name = 'secupress-temporary-file-' . secupress_generate_hash( 'file_name', 2, 6 ) . '.' . $file_ext;
		$file_path = $basedir . '/' . $file_name;

		// Create the file.
		if ( file_exists( $file_path ) ) {
			$wp_filesystem->delete( $file_path );
		}
		if ( ! file_exists( $basedir ) ) {
			$wp_filesystem->mkdir( $basedir, FS_CHMOD_DIR );
		}
		if ( file_exists( $file_path ) || ! file_exists( $basedir ) ) {
			return;
		}

		$created = $wp_filesystem->put_contents( $file_path, 'Temporary file', FS_CHMOD_FILE );

		if ( $created ) {
			$this->file_path = $file_path;
			$this->file_url  = trailingslashit( $uploads['baseurl'] ) . $file_name;
		}
	}


	/**
	 * Delete a file.
	 *
	 * @since 1.0
	 */
	protected function delete_file() {
		secupress_get_filesystem()->delete( $this->file_path );

		$this->file_path = false;
		$this->file_url  = false;
	}
}
