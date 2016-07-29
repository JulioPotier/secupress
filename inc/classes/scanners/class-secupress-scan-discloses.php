<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Discloses scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Discloses extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */


	/** Properties. ============================================================================= */

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
		global $is_apache, $is_nginx, $is_iis7;

		$this->title = __( 'Check if your WordPress site discloses its version.', 'secupress' );
		$this->more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );

		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif ( $is_iis7 ) {
			$config_file = 'web.config';
		} elseif ( ! $is_nginx ) {
			$this->fixable = false;
		}

		if ( $this->fixable ) {
			$this->more_fix  = __( 'Depending of the scan results, one (or all) of the following will be applied:', 'secupress' ) . '<br/>';
		} else {
			$this->more_fix = static::get_messages( 301 );
		}

		if ( $is_nginx ) {
			$this->more_fix .= sprintf( __( 'THe %s file cannot be edited automatically, this will give you the rules to add into it manually, to avoid attackers to read sensitive informations from your installation.', 'secupress' ), '<code>nginx.conf</code>' ) . '<br/>';
		} elseif ( $this->fixable ) {
			$this->more_fix .= sprintf( __( 'Add rules in your %s file to avoid attackers to read sensitive informations from your installation.', 'secupress' ), "<code>$config_file</code>" ) . '<br/>';
		}

		if ( $this->fixable ) {
			$this->more_fix .= __( 'The meta tag containing the WordPress version may be removed.', 'secupress' ) . '<br/>';
			$this->more_fix .= __( 'The WordPress version may be removed from the styles and scripts URL.', 'secupress' ) . '<br/>';
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
			0   => __( 'Your site does not reveal sensitive informations.', 'secupress' ),
			1   => __( 'The website does not display the <strong>PHP version</strong> in the request headers anymore.', 'secupress' ),
			/* translators: %s is a file name */
			2   => sprintf( __( 'The %s file is now protected from revealing sensitive informations.', 'secupress' ), '<code>readme.html</code>' ),
			/* translators: 1 is a file name */
			3   => __( 'As the rules against the PHP version disclosure added to your %s file do not seem to work, another plugin has been activated to remove this information in some other way.', 'secupress' ),
			4   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			5   => __( 'The WordPress version should now be removed from your styles URL.', 'secupress' ),
			6   => __( 'The WordPress version should now be removed from your scripts URL.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			/* translators: %s is an URL */
			101 => sprintf( __( 'Unable to determine status of %s, it is still revealing sensitive informations.', 'secupress' ), '<code>' . home_url( 'readme.html' ) . '</code>' ),
			// "bad"
			200 => __( 'The website displays the <strong>PHP version</strong> in the request headers.', 'secupress' ),
			201 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code (%s).', 'secupress' ),
			/* translators: %s is an URL */
			202 => sprintf( __( '<code>%s</code> should not be accessible by anyone to avoid revealing sensitive informations.', 'secupress' ), home_url( 'readme.html' ) ),
			// "cantfix"
			/* translators: 1 is a file name, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the sensitive information disclosure cannot be fixed automatically but you can do it yourself by adding the following code into your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs a non recognized system. The sensitive information disclosure cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 is a file name, 2 is some code */
			302 => __( 'Your %1$s file does not seem to be writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
			/* translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code */
			303 => __( 'Your %1$s file does not seem to be writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ),
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
		global $is_nginx;

		$wp_version   = get_bloginfo( 'version' );
		$php_version  = phpversion();
		$wp_discloses = array();
		$is_bad       = false;

		// Get home page contents. ==========================.
		$response     = wp_remote_get( add_query_arg( time(), time(), user_trailingslashit( home_url() ) ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );
		} else {
			// "warning"
			$this->add_message( 100 );
		}

		// PHP version in headers. ==========================.
		if ( $has_response && false !== strpos( $powered_by, $php_version ) ) {
			// "bad"
			$this->add_message( 200 );
			$is_bad = true;
		}

		// WordPress version in homepage source code. =======.
		if ( $has_response ) {
			// Meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "bad"
				$wp_discloses[] = 'META';
			}
		}

		// Style tag src.
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "bad"
			$wp_discloses[] = 'CSS';
		}

		// Script tag src.
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		/** This filter is documented in wp-includes/class.wp-scripts.php */
		if ( apply_filters( 'script_loader_src', $script_url, 'secupress' ) === $script_url ) {
			// "bad"
			$wp_discloses[] = 'JS';
		}

		// Sum up!
		if ( $wp_discloses ) {
			// "bad"
			$this->add_message( 201, array( $wp_discloses ) );
			$is_bad = true;
		}

		// Readme file. =====================================.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$this->add_message( 202 );
				$is_bad = true;
			}
		} else {
			// "warning"
			$this->add_message( 101 );
		}

		if ( $is_bad && ! $this->fixable ) {
			$this->add_pre_fix_message( 301 );
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

		$todo        = array();
		$wp_version  = get_bloginfo( 'version' );
		$php_version = phpversion();

		// Get home page contents. ==========================.
		$response     = wp_remote_get( add_query_arg( time(), time(), user_trailingslashit( home_url() ) ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );
		} else {
			// "warning"
			$this->add_fix_message( 100 );
		}

		// PHP version in headers. ==========================.
		if ( $has_response && false !== strpos( $powered_by, $php_version ) ) {
			$todo['php_version'] = 1;
		}

		// WordPress version in homepage source code. =======.
		if ( $has_response ) {
			// Meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "good"
				secupress_activate_submodule( 'discloses', 'generator' );
				$this->add_fix_message( 4 );
			}
		}

		// Style tag src.
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "good"
			secupress_activate_submodule( 'discloses', 'wp-version-css' );
			$this->add_fix_message( 5 );
		}

		// Script tag src.
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		/** This filter is documented in wp-includes/class.wp-scripts.php */
		if ( apply_filters( 'script_loader_src', $script_url, 'secupress' ) === $script_url ) {
			// "good"
			secupress_activate_submodule( 'discloses', 'wp-version-js' );
			$this->add_fix_message( 6 );
		}

		// Readme file. =====================================.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				$todo['readme'] = 1;
			}
		} else {
			// "warning"
			$this->add_fix_message( 101 );
		}

		if ( $todo ) {
			if ( $is_apache ) {
				$this->_fix_apache( $todo );
			} elseif ( $is_iis7 ) {
				$this->_fix_iis7( $todo );
			} elseif ( $is_nginx ) {
				$this->_fix_nginx( $todo );
			}
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/**
	 * Fix for Apache system.
	 *
	 * @since 1.0
	 *
	 * @param (array) $todo Tasks to do.
	 */
	protected function _fix_apache( $todo ) {
		global $wp_settings_errors;

		// PHP version disclosure in header.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
				// "cantfix"
				$this->add_fix_message( 302, array( '<code>.htaccess</code>', static::_get_rules_from_error( $last_error ) ) );
				array_pop( $wp_settings_errors );
			} else {
				// Succeed: now test our rule against php version disclosure works.
				$this->_scan_php_disclosure(); // Fix message 1 or 3 inside.
			}
		}

		// `readme.html` file.
		if ( isset( $todo['readme'] ) ) {
			secupress_activate_submodule( 'discloses', 'readmes' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
				// "cantfix"
				$this->add_fix_message( 302, array( '<code>.htaccess</code>', static::_get_rules_from_error( $last_error ) ) );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 2 );
			}
		}
	}


	/**
	 * Fix for IIS7 system.
	 *
	 * @since 1.0
	 */
	protected function _fix_iis7() {
		global $wp_settings_errors;

		// PHP version disclosure in header.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
				// "cantfix"
				$this->add_fix_message( 303, array( '<code>.htaccess</code>', static::_get_rules_from_error( $last_error ) ) );
				array_pop( $wp_settings_errors );
			} else {
				// Succeed: now test our rule against php version disclosure works.
				$this->_scan_php_disclosure(); // Fix message 1 or 3 inside.
			}
		}

		// `readme.html` file.
		if ( isset( $todo['readme'] ) ) {
			secupress_activate_submodule( 'discloses', 'readmes' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
				// "cantfix"
				$this->add_fix_message( 303, array( '<code>.htaccess</code>', static::_get_rules_from_error( $last_error ) ) );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 2 );
			}
		}
	}


	/**
	 * Fix for nginx system.
	 *
	 * @since 1.0
	 */
	protected function _fix_nginx() {
		global $wp_settings_errors;
		$all_rules = array();

		// PHP version disclosure in header.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
			$rules      = '<code>Error</code>';

			if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
				$rules = static::_get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			}

			$all_rules[] = $rules;
		}

		// `readme.html` file.
		if ( isset( $todo['readme'] ) ) {
			secupress_activate_submodule( 'discloses', 'readmes' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
			$rules      = '<code>Error</code>';

			if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
				$rules = static::_get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			}

			$all_rules[] = $rules;
		}

		if ( $all_rules ) {
			$all_rules = implode( ' ', $all_rules );
			// "cantfix"
			$this->add_fix_message( 300, array( $all_rules ) );
		}
	}


	/** Tools. ================================================================================== */

	/**
	 * Scan for php version disclosure in head.
	 *
	 * @since 1.0
	 */
	protected function _scan_php_disclosure() {
		global $is_apache;

		$response_test = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );

		if ( is_wp_error( $response_test ) || 200 !== wp_remote_retrieve_response_code( $response_test ) ) {
			return;
		}

		$powered_by  = wp_remote_retrieve_header( $response_test, 'x-powered-by' );
		$php_version = phpversion();

		if ( false === strpos( $powered_by, $php_version ) ) {
			// Test is ok.
			// "good".
			$this->add_fix_message( 1 );
		} else {
			// Test failed, try another way.
			secupress_activate_submodule( 'discloses', 'php-version' );
			$file = $is_apache ? '.htaccess' : 'web.config';
			// "good"
			$this->add_fix_message( 3, array( "<code>$file</code>" ) );
		}
	}
}
