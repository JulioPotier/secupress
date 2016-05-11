<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PHP Disclosure scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_PHP_Disclosure extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	protected static function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses the PHP modules <em>(know as PHP Easter Egg)</em>.', 'secupress' );
		self::$more  = __( 'PHP contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered when a remote attacker makes certain HTTP requests with crafted arguments, which will disclose PHP version and another sensitive information resulting in a loss of confidentiality.', 'secupress' );

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
			0   => __( 'Your site does not reveal the PHP modules.', 'secupress' ),
			1   => __( 'Your %s file has been successfully edited.', 'secupress' ),
			// "warning"
			100 => sprintf( __( 'Unable to determine status of %s.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// "bad"
			200 => sprintf( __( '%s should not be accessible to anyone.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// "cantfix"
			/* translators: 1 is a file name, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the sensitive information disclosure cannot be fixed automatically but you can do it yourself by adding the following code into your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs a non recognized system. The sensitive information disclosure cannot be fixed automatically.', 'secupress' ),
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
		// - http://osvdb.org/12184
		$response = wp_remote_get( user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000', array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$response_body = wp_remote_retrieve_body( $response );

			if ( strpos( $response_body, '<h1>PHP Credits</h1>' ) > 0 && strpos( $response_body, '<title>phpinfo()</title>' ) > 0 ) {
				// "bad"
				$this->add_message( 200 );

				if ( ! self::$fixable ) {
					$this->add_pre_fix_message( 301 );
				}
			}
		} elseif ( is_wp_error( $response ) ) {
			// If it's not an error, then no disclose.
			// "warning".
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

		secupress_activate_submodule( 'sensitive-data', 'php-easter-egg' );

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

		secupress_activate_submodule( 'sensitive-data', 'php-easter-egg' );

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

		secupress_activate_submodule( 'sensitive-data', 'php-easter-egg' );

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
