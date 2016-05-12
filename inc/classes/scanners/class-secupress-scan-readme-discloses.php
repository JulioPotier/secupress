<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * `readme.txt` disclose scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Readme_Discloses extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	public    static $prio = 'medium';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected static function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = __( 'Plugins and Themes', 'secupress' );
		/* translators: %s is a file name */
		self::$title = sprintf( __( 'Check if the %s files from your plugins and themes are protected.', 'secupress' ), '<code>readme.txt</code>' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 ) {
			$config_file = 'web.config';
		} elseif ( ! $is_nginx ) {
			self::$fixable = false;
		}

		if ( $is_nginx ) {
			self::$more_fix = sprintf( __( 'Since your %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to read sensitive informations from your installation.', 'secupress' ), '<code>nginx.conf</code>' );
		} elseif ( self::$fixable ) {
			self::$more_fix = sprintf( __( 'This will add rules in your %s file to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" );
		} else {
			self::$more_fix = static::get_messages( 301 );
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
			/* translators: %s is a file name */
			0   => sprintf( __( 'The %s files are protected.', 'secupress' ), '<code>readme.txt</code>' ),
			/* translators: 1 and 2 are file names */
			1   => sprintf( __( 'The rules forbidding access to your %1$s files have been successfully added to your %2$s file.', 'secupress' ), '<code>readme.txt</code>', '%s' ),
			// "warning"
			/* translators: %s is a file name */
			100 => sprintf( __( 'Unable to determine status of the %s files.', 'secupress' ), '<code>readme.txt</code>' ),
			// "bad"
			/* translators: %s is a file name */
			200 => sprintf( __( 'The %s files should not be accessible to anyone.', 'secupress' ), '<code>readme.txt</code>' ),
			// "cantfix"
			/* translators: 1 and 2 are a file names, 3 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the %1$s files cannot be protected automatically but you can do it yourself by adding the following code into your %2$s file: %3$s', 'secupress' ), '<code>readme.txt</code>', '<code>nginx.conf</code>', '%s' ),
			/* translators: %s is a file name */
			301 => sprintf( __( 'Your server runs a non recognized system. The %s files cannot be protected automatically.', 'secupress' ), '<code>readme.txt</code>' ),
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
		$protected = static::_are_files_protected();

		if ( is_null( $protected ) ) {
			// "warning"
			$this->add_message( 100 );

		} elseif ( ! $protected ) {
			// "bad"
			$this->add_message( 200 );

			if ( ! self::$fixable ) {
				$this->add_pre_fix_message( 301 );
			}
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

		$protected = static::_are_files_protected();

		if ( is_null( $protected ) ) {
			// "warning"
			$this->add_fix_message( 100 );
			return parent::fix();
		}

		if ( $protected ) {
			// "good"
			$this->add_fix_message( 0 );
			return parent::fix();
		}

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

		secupress_activate_submodule( 'discloses', 'readmes' );

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

		secupress_activate_submodule( 'discloses', 'readmes' );

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

		secupress_activate_submodule( 'discloses', 'readmes' );

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
	 * Tells if the readme files are accessible.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	protected static function _are_files_protected() {
		// Get all readme/changelog files.
		$plugins = rtrim( secupress_get_plugins_path(), '\\/' );
		$themes  = rtrim( secupress_get_themes_path(), '\\/' );
		$pattern = '{' . $plugins . ',' . $themes . '}/*/{README,CHANGELOG,readme,changelog}.{TXT,MD,HTML,txt,md,html}';
		$files   = glob( $pattern, GLOB_BRACE );

		// No file? Good, nothing to protect.
		if ( ! $files ) {
			// "good".
			return true;
		}

		// Get the first file path, relative to the root of the site.
		$abspath = wp_normalize_path( ABSPATH );
		$file    = reset( $files );
		if ( isset( $files[1] ) && false !== strpos( $file, '/akismet/' ) ) {
			// Akismet protects its files.
			$file = $files[1];
		}
		$file    = wp_normalize_path( $file );
		$file    = ltrim( str_replace( $abspath, '', $file ), '/' );

		// Get file contents.
		$response = wp_remote_get( site_url( $file ), array( 'redirection' => 0 ) );

		if ( is_wp_error( $response ) ) {
			// "warning".
			return null;
		} elseif ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			// "bad".
			return false;
		}
		// "good".
		return true;
	}
}
