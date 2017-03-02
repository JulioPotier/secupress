<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Directory Index scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_DirectoryIndex extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.3';


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
		global $is_apache, $is_nginx, $is_iis7;

		/** Translators: 1, 2 and 3 are file extensions. */
		$this->title    = sprintf( __( 'Check if %1$s files are loaded with a higher priority over %2$s or %3$s etc.', 'secupress' ), '<em>.php</em>', '<em>.html</em>', '<em>.htm</em>' );
		/** Translators: 1 and 2 are file names. */
		$this->more     = sprintf( __( 'If your website is the victim of defacement using the addition of a file like %1$s, this file could be loaded first instead of the one from WordPress. This is why your website has to load %2$s first.', 'secupress' ), '<code>index.htm</code>', '<code>index.php</code>' );
		$this->more_fix = sprintf(
			__( 'Activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Directory Index', 'secupress' ) . '</strong>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'file-system' ) ) . '#row-directory-index_activated">' . __( 'Malware Scan', 'secupress' ) . '</a>'
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
			'<strong>' . __( 'Directory Index', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'file-system' ) ) . '#row-directory-index_activated">' . __( 'Malware Scan', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			/** Translators: %s is a file name. */
			0   => sprintf( __( '%s is the first file loaded, index file order is good.', 'secupress' ), '<code>index.php</code>' ),
			/** Translators: %s is a file name. */
			1   => sprintf( __( 'The rules to get the correct index file order (known as Directory Index) have been successfully added to your %s file.', 'secupress' ), "<code>$config_file</code>" ),
			// "warning"
			100 => __( 'Unable to determine the status of the index file order.', 'secupress' ) . ' ' . $activate_protection_message,
			// "bad"
			/** Translators: 1 and 2 are file names. */
			200 => sprintf( __( 'Your website should load %1$s first, but actually it loads %2$s first.', 'secupress' ), '<code>index.php</code>', '%s' ),
			// "cantfix"
			/** Translators: 1 is a file name, 2 is some code. */
			300 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the index file order cannot be fixed automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs an unrecognized system. The index file order cannot be fixed automatically.', 'secupress' ),
			/** Translators: 1 is a file name, 2 is some code. */
			302 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ), "<code>$config_file</code>", '%s' ),
			/** Translators: 1 is a file name, 2 is a tag name, 3 is a folder path (kind of), 4 is some code. */
			303 => sprintf( __( 'Your %1$s file is not writable. Please remove any previous %2$s tag and add the following lines inside the tags hierarchy %3$s (create it if does not exist): %4$s', 'secupress' ), "<code>$config_file</code>", '%1$s', '%2$s', '%3$s' ),
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
		return __( 'http://docs.secupress.me/article/123-index-file-priority-scan', 'secupress' );
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
		$request_args = $this->get_default_request_args();
		$request_args['redirection'] = 1;
		$response     = wp_remote_get( SECUPRESS_INC_URL . 'DirectoryIndex', $request_args ); // Create the folder at root ////.

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$response_body = trim( wp_remote_retrieve_body( $response ) );

			if ( 'index.php' !== $response_body ) {
				// "bad"
				$this->add_message( 200, array( '<code>' . esc_html( $response_body ) . '</code>' ) );

				if ( ! $this->fixable ) {
					$this->add_pre_fix_message( 301 );
				}
			}
		} else {
			// "warning"
			$this->add_message( 100 );
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
		global $is_apache, $is_nginx, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		} elseif ( $is_nginx ) {
			$this->fix_nginx();
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/**
	 * Fix for Apache system.
	 *
	 * @since 1.0
	 */
	protected function fix_apache() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'directory-index' );

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

		secupress_activate_submodule( 'file-system', 'directory-index' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
			$rules     = static::get_rules_from_error( $last_error );
			$path      = static::get_code_tag_from_error( $last_error, 'secupress-iis7-path' );
			$node_type = static::get_code_tag_from_error( $last_error, 'secupress-iis7-node-type' );
			// "cantfix"
			$this->add_fix_message( 303, array( $node_type, $path, $rules ) );
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

		secupress_activate_submodule( 'file-system', 'directory-index' );

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
}
