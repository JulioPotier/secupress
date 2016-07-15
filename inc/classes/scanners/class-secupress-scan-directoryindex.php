<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * DirectoryIndex scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_DirectoryIndex extends SecuPress_Scan implements SecuPress_Scan_Interface {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Priority.
	 *
	 * @var (string)
	 */
	public    static $prio    = 'low';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = 'WordPress';
		self::$title = __( 'Check if <em>.php</em> files are loaded in priority instead of <em>.html</em> or <em>.htm</em> etc.', 'secupress' );
		self::$more  = sprintf( __( 'If your website is victim of a defacement using the addition of a file like %1$s, this file could be loaded first instead of the one from WordPress. This is why we have to load %2$s first..', 'secupress' ), '<code>index.htm</code>', '<code>index.php</code>' );

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 ) {
			$config_file = 'web.config';
		} elseif ( ! $is_nginx ) {
			$this->fixable = false;
		}

		if ( $is_nginx ) {
			$this->more_fix = sprintf( __( 'Since your %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to load <code>.html</code>/<code>.htm</code> files before the <code>.php</code> one.', 'secupress' ), '<code>nginx.conf</code>' );
		} elseif ( $this->fixable ) {
			$this->more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to load <code>.html</code>/<code>.htm</code> files before the <code>.php</code> one.', 'secupress' ), "<code>$config_file</code>" );
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
			0   => sprintf( __( '%s is the first file loaded, perfect.', 'secupress' ), '<code>index.php</code>' ),
			1   => __( 'Your %s file has been successfully edited.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine status of the directory index.', 'secupress' ),
			// "bad"
			200 => sprintf( __( 'Your website should load %1$s first, actually it loads %2$s first.', 'secupress' ), '<code>index.php</code>', '%s' ),
			// "cantfix"
			/* translators: 1 is a file name, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the directory index cannot be fixed automatically but you can do it yourself by adding the following code into your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs a non recognized system. The directory index cannot be fixed automatically.', 'secupress' ),
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
		$response = wp_remote_get( SECUPRESS_PLUGIN_URL . 'inc/DirectoryIndex', array( 'redirection' => 1 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$response_body = wp_remote_retrieve_body( $response );

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
	protected function _fix_apache() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'file-system', 'directory-index' );

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

		secupress_activate_submodule( 'file-system', 'directory-index' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
			// "cantfix"
			$this->add_fix_message( 303, array( '<code>web.config</code>', '/configuration/system.webServer', static::_get_rules_from_error( $last_error ) ) );
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

		secupress_activate_submodule( 'file-system', 'directory-index' );

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
}
