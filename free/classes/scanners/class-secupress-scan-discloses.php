<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Discloses scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Discloses extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		global $is_apache, $is_nginx, $is_iis7;

		$module_url     = esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) );
		$this->title    = __( 'Check if your site discloses your WordPress version and your server’s PHP version.', 'secupress' );
		$this->more     = __( 'When an attacker wants to hack into a WordPress site, they will search for all available informations. The goal is to find something useful that will help him penetrate your site. Don’t let them easily find any informations.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the %1$s protection and/or the %2$s protection from the module %3$s.', 'secupress' ),
			'<a href="' . $module_url . '#row-content-protect_wp-version">' . __( 'WordPress Version Disclosure', 'secupress' ) . '</a>',
			'<a href="' . $module_url . '#row-content-protect_php-version">' . __( 'PHP Version Disclosure', 'secupress' ) . '</a>',
			'<strong>' . __( 'Sensitive Data', 'secupress' ) . '</strong>'
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
		$module_url = esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) );
		/** Translators: 1 and 2 are the name of protections, 3 is the name of a module. */
		$activate_protections_message = sprintf( __( 'But you can activate the %1$s protection and the %2$s protection from the module %3$s.', 'secupress' ),
			'<a target="_blank" href="' . $module_url . '#row-content-protect_wp-version">' . __( 'WordPress Version Disclosure', 'secupress' ) . '</a>',
			'<a target="_blank" href="' . $module_url . '#row-content-protect_php-version">' . __( 'PHP Version Disclosure', 'secupress' ) . '</a>',
			'<strong>' . __( 'Sensitive Data', 'secupress' ) . '</strong>'
		);
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'WordPress Version Disclosure', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . $module_url . '#row-content-protect_wp-version">' . __( 'WordPress Version Disclosure', 'secupress' ) . '</a>'
		);

		$messages   = array(
			// "good"
			0   => __( 'Your site does not reveal either your <strong>WordPress version</strong> or <strong>PHP version</strong>.', 'secupress' ),
			1   => __( 'The protection preventing your site to disclose your <strong>PHP version</strong> has been activated.', 'secupress' ),
			7   => __( 'The protection preventing your site to disclose your <strong>WordPress version</strong> has been activated.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine if your homepage is disclosing your <strong>WordPress version</strong> or <strong>PHP version</strong>.', 'secupress' ) . ' ' . $activate_protections_message,
			/** Translators: %s is a file name. */
			101 => sprintf( __( 'Unable to determine if the %s file is disclosing your <strong>WordPress version</strong>.', 'secupress' ), '<code>readme.html</code>' ) . ' ' . $activate_protection_message,
			// "bad"
			200 => __( 'The website displays the <strong>PHP version</strong> in the request headers.', 'secupress' ),
			201 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code (%s).', 'secupress' ),
			/** Translators: %s is a file name. */
			202 => sprintf( __( 'The %s file should not be accessible by anyone to avoid to reveal your <strong>WordPress version</strong>.', 'secupress' ), '<code>readme.html</code>' ),
			// "cantfix"
			/** Translators: 1 is a file name, 2 is some code. */
			300 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the <strong>WordPress version</strong> and <strong>PHP version</strong> disclosure cannot be fixed automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			/** Translators: 1 is a file name, 2 is some code. */
			302 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ), '<code>.htaccess</code>', '%s' ),
			/** Translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code. */
			303 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ), '<code>web.config</code>', '%1$s', '%2$s' ),
			/** Translators: 1 is a file name, 2 is some code. */
			304 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the <strong>PHP version</strong> disclosure cannot be fixed automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			/** Translators: 1 is a file name, 2 is some code. */
			305 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the <strong>WordPress version</strong> disclosure cannot be fixed automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			// DEPRECATED, NOT IN USE ANYMORE.
			/** Translators: %s is a file name. */
			2   => sprintf( __( 'The %s file is now protected from revealing your <strong>WordPress version</strong>.', 'secupress' ), '<code>readme.html</code>' ),
			3   => __( 'The website does not display the <strong>PHP version</strong> in the request headers anymore.', 'secupress' ),
			4   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			5   => __( 'The <strong>WordPress version</strong> should now be removed from your styles URLs.', 'secupress' ),
			6   => __( 'The <strong>WordPress version</strong> should now be removed from your scripts URLs.', 'secupress' ),
			301 => __( 'Your server runs an unrecognized system. The <strong>WordPress version</strong> and <strong>PHP version</strong> disclosure cannot be fixed automatically.', 'secupress' ),
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
		return __( 'https://docs.secupress.me/article/101-php-and-wordpress-version-disclosure-scan', 'secupress' );
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

		global $is_nginx;

		$wp_version   = get_bloginfo( 'version' );
		$php_version  = phpversion();
		$wp_discloses = array();

		// Get home page contents. ==========================.
		$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), $this->get_default_request_args() );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$powered_by = is_array( $powered_by ) ? reset( $powered_by ) : $powered_by;
			$body       = wp_remote_retrieve_body( $response );
		}

		// WordPress version in generator meta tag. =========.
		if ( $has_response ) {
			// Meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "bad"
				$wp_discloses[] = 'META';
			}
		}

		// Style tag src. ===================================.
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "bad"
			$wp_discloses[] = 'CSS';
		}

		// Script tag src. ==================================.
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
		$response = wp_remote_get( site_url( 'readme.html' ), $this->get_default_request_args() );

		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$this->add_message( 202 );
			}
		}

		// PHP version in headers. ==========================.
		if ( $has_response && false !== strpos( $powered_by, $php_version ) ) {
			// "bad"
			$this->add_message( 200 );
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
		global $is_apache, $is_nginx, $is_iis7;

		$wp_version  = get_bloginfo( 'version' );
		$php_version = phpversion();
		$todo        = array();

		// Get home page contents. ==========================.
		$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), $this->get_default_request_args() );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			if ( is_array( $powered_by ) ) {
				foreach( $powered_by as $p ) {
					if ( strpos( $p, 'PHP/' ) === 0 ) {
						$powered_by = $p;
						break;
					}
				}
			}
			$body       = wp_remote_retrieve_body( $response );
		}

		// WordPress version in generator meta tag. =========.
		if ( $has_response ) {
			// Meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( array_filter( $matches ) ) {
				$todo['wp_version'] = 1;
			}
		}

		// Style tag src. ===================================.
		if ( empty( $todo['wp_version'] ) ) {
			$style_url = home_url( '/fake.css?ver=' . $wp_version );

			/** This filter is documented in wp-includes/class.wp-styles.php */
			if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
				$todo['wp_version'] = 1;
			}
		}

		// Script tag src. ==================================.
		if ( empty( $todo['wp_version'] ) ) {
			$script_url = home_url( '/fake.js?ver=' . $wp_version );

			/** This filter is documented in wp-includes/class.wp-scripts.php */
			if ( apply_filters( 'script_loader_src', $script_url, 'secupress' ) === $script_url ) {
				$todo['wp_version'] = 1;
			}
		}

		// Readme file. =====================================.
		if ( empty( $todo['wp_version'] ) ) {
			$response = wp_remote_get( site_url( 'readme.html' ), $this->get_default_request_args() );

			if ( ! is_wp_error( $response ) ) {
				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					$todo['wp_version'] = 1;
				}
			} else {
				// "warning"
				$this->add_fix_message( 101 );
			}
		}

		// PHP version in headers. ==========================.
		if ( $has_response && false !== strpos( $powered_by, $php_version ) ) {
			$todo['php_version'] = 1;
		}

		if ( $todo ) {
			if ( $is_apache ) {
				$this->fix_apache( $todo );
			} elseif ( $is_iis7 ) {
				$this->fix_iis7( $todo );
			} elseif ( $is_nginx ) {
				$this->fix_nginx( $todo );
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
	protected function fix_apache( $todo ) {
		global $wp_settings_errors;
		$all_rules = array();

		// WP version disclosure.
		if ( isset( $todo['wp_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'wp-version' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
				$all_rules[] = static::get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 7 );
			}
		}

		// PHP version disclosure.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
				$all_rules[] = static::get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 1 );
			}
		}

		if ( $all_rules ) {
			$all_rules = implode( "\n", $all_rules );
			// "cantfix"
			$this->add_fix_message( 302, array( $all_rules ) );
		}
	}


	/**
	 * Fix for IIS7 system.
	 *
	 * @since 1.0
	 *
	 * @param (array) $todo Tasks to do.
	 */
	protected function fix_iis7( $todo ) {
		global $wp_settings_errors;

		// WP version disclosure.
		if ( isset( $todo['wp_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'wp-version' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
				$rules = static::get_rules_from_error( $last_error );
				$path  = static::get_code_tag_from_error( $last_error, 'secupress-iis7-path' );
				// "cantfix"
				$this->add_fix_message( 303, array( $path, $rules ) );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 7 );
			}
		}

		// PHP version disclosure.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Got error?
			$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

			if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
				$rules = static::get_rules_from_error( $last_error );
				$path  = static::get_code_tag_from_error( $last_error, 'secupress-iis7-path' );
				// "cantfix"
				$this->add_fix_message( 303, array( $path, $rules ) );
				array_pop( $wp_settings_errors );
			} else {
				// "good"
				$this->add_fix_message( 1 );
			}
		}
	}


	/**
	 * Fix for nginx system.
	 *
	 * @since 1.0
	 *
	 * @param (array) $todo Tasks to do.
	 */
	protected function fix_nginx( $todo ) {
		global $wp_settings_errors;

		// WP version disclosure.
		if ( isset( $todo['wp_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'wp-version' );

			// Get the error.
			$last_error         = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
			$todo['wp_version'] = '<code>Error</code>';

			if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
				$todo['wp_version'] = static::get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			}
		}

		// PHP version disclosure.
		if ( isset( $todo['php_version'] ) ) {
			secupress_activate_submodule( 'discloses', 'no-x-powered-by' );

			// Get the error.
			$last_error          = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
			$todo['php_version'] = '<code>Error</code>';

			if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
				$todo['php_version'] = static::get_rules_from_error( $last_error );
				array_pop( $wp_settings_errors );
			}
		}

		if ( isset( $todo['php_version'], $todo['wp_version'] ) ) {
			$todo = implode( "\n", $todo );
			// "cantfix"
			$this->add_fix_message( 300, array( $todo ) );
		} elseif ( isset( $todo['php_version'] ) ) {
			// "cantfix"
			$this->add_fix_message( 304, array_values( $todo ) );
		} else {
			// "cantfix"
			$this->add_fix_message( 305, array_values( $todo ) );
		}
	}
}
