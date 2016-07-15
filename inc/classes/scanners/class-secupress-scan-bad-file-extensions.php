<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad File Extensions scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_File_Extensions extends SecuPress_Scan implements SecuPress_Scan_Interface {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
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


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = 'WordPress';
		$this->title = __( 'Check if some files that use bad extensions are reachable in the uploads folder.', 'secupress' );
		$this->more  = __( 'The uploads folder should contain only files like images, pdf, or zip archives. Some other files should not be placed inside this folder, or at least, should not be reachable by their URL.', 'secupress' );

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 ) {
			$config_file = 'web.config';
		} elseif ( ! $is_nginx ) {
			$this->fixable = false;
		}

		if ( $is_nginx ) {
			$this->more_fix = sprintf( __( 'Since your %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to read sensitive informations from your installation.', 'secupress' ), '<code>nginx.conf</code>' );
		} elseif ( $this->fixable ) {
			$this->more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} else {
			$this->more_fix = static::get_messages( 301 );
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
		$messages = array(
			// "good"
			0   => __( 'Files that use bad extensions are protected.', 'secupress' ),
			/* translators: 1 is a file name */
			1   => sprintf( __( 'The rules forbidding access to files that use bad extensions have been successfully added to your %s file.', 'secupress' ), '%s' ),
			// "warning"
			100 => __( 'Unable to determine status of the test file.', 'secupress' ),
			// "bad"
			200 => __( 'Could not create a test file in the uploads folder.', 'secupress' ),
			201 => __( 'Files that use bad extensions are reachable in the uploads folder.', 'secupress' ),
			// "cantfix"
			/* translators: 1 is a file names, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the files that use bad extensions cannot be protected automatically but you can do it yourself by adding the following code into your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs a non recognized system. The files that use bad extensions cannot be protected automatically.', 'secupress' ),
			/* translators: 1 is a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
			/* translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code */
			303 => __( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		// Create the temporary file.
		$this->_create_file();

		if ( ! $this->file_url ) {
			// "bad"
			$this->add_message( 200 );
			return parent::scan();
		}

		$response = wp_remote_get( $this->file_url, array( 'redirection' => 0 ) );

		if ( is_wp_error( $response ) ) {
			// "warning"
			$this->add_message( 100 );

		} elseif ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			// "bad"
			$this->add_message( 201 );
		}

		// Delete the temporary file.
		$this->_delete_file();

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
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
			$this->_fix_apache();
		} elseif ( $is_iis7 ) {
			$this->_fix_iis7();
		} elseif ( $is_nginx ) {
			$this->_fix_nginx();
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
	protected function _fix_apache() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
			// "cantfix"
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', static::_get_rules_from_error( $last_error ) ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
	}


	/**
	 * Fix for IIS7 system.
	 *
	 * @since 1.0
	 */
	protected function _fix_iis7() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
			// "cantfix"
			$this->add_fix_message( 303, array( '<code>web.config</code>', '/configuration/system.webServer/rewrite/rules', static::_get_rules_from_error( $last_error ) ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
	}


	/**
	 * Fix for nginx system.
	 *
	 * @since 1.0
	 */
	protected function _fix_nginx() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'bad-file-extensions' );

		// Get the error.
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
		$rules      = '<code>Error</code>';

		if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
			$rules = static::_get_rules_from_error( $last_error );
			array_pop( $wp_settings_errors );
		}

		// "cantfix"
		$this->add_fix_message( 300, array( $rules ) );
	}


	/**
	 * Create a test file in the uploads folder. Also set the test file path and URL.
	 *
	 * @since 1.0
	 */
	protected function _create_file() {
		$wp_filesystem = secupress_get_filesystem();
		$uploads       = wp_upload_dir( null, false );
		$basedir       = wp_normalize_path( $uploads['basedir'] );
		$extensions    = secupress_bad_file_extensions_get_forbidden_extensions();

		// Get the file name.
		$file_ext  = mt_rand( 0, count( $extensions ) - 1 );
		$file_ext  = $extensions[ $file_ext ];
		$file_name = 'secupress-' . secupress_generate_hash( 'file_name', 2, 6 ) . '.' . $file_ext;
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
	 * Tells if the readme files are accessible. Also falsy the test file path and URL.
	 *
	 * @since 1.0
	 */
	protected function _delete_file() {
		secupress_get_filesystem()->delete( $this->file_path );

		$this->file_path = false;
		$this->file_url  = false;
	}
}
