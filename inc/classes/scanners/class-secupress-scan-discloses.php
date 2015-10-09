<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Discloses scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses its version.', 'secupress' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. The goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your site does not reveal sensitive informations.', 'secupress' ),
			1   => __( 'The rules against the php version disclosure have been successfully added to your %s file.', 'secupress' ),
			2   => __( 'As the rules against the php version disclosure added to your %s file do not seem to work, we remove this information directly with php.', 'secupress' ),
			3   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			4   => __( 'The WordPress version should be removed from your styles URL now.', 'secupress' ),
			5   => __( 'The WordPress version should be removed from your scripts URL now.', 'secupress' ),
			6   => __( 'The rules forbidding access to your %1$s file have been successfully added to your %2$s file.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			101 => sprintf( __( 'Unable to determine status of %s.', 'secupress' ), '<code>' . home_url( 'readme.html' ) . '</code>' ),
			// bad
			200 => __( 'The website displays the <strong>PHP version</strong> in the request headers.', 'secupress' ),
			201 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code (%s).', 'secupress' ),
			202 => sprintf( __( '<code>%s</code> should not be accessible by anyone.', 'secupress' ), home_url( 'readme.html' ) ),
			// cantfix
			300 => sprintf( __( 'You run a nginx system, I cannot fix the PHP version disclosure in headers but you can do it yourself with the following code: %s.', 'secupress' ), '<code>(add nginx code here)</code>' ), ////
			301 => sprintf( __( 'You run an IIS7 system, I cannot fix the PHP version disclosure in headers but you can do it yourself with the following code: %s.', 'secupress' ), '<code>(add IIS code here)</code>' ), //// iis7_url_rewrite_rules ?
			302 => __( 'You don\'t run an Apache system, I cannot fix the PHP version disclosure in headers.', 'secupress' ),
			303 => __( 'Your %1$s file is not writable. Please add the following lines to the file: %2$s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$wp_version   = get_bloginfo( 'version' );
		$php_version  = phpversion();
		$wp_discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );
		} else {
			// warning
			$this->add_message( 100 );
		}

		// Generator meta tag + php header
		if ( $has_response ) {

			// PHP version in headers.
			if ( false !== strpos( $powered_by, $php_version ) ) {
				// bad
				$this->add_message( 200 );
			}

			// WordPress version in meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( count( array_filter( $matches ) ) ) {
				// bad
				$wp_discloses[] = 'META';
			}

		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// bad
			$wp_discloses[] = 'CSS';
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// bad
			$wp_discloses[] = 'JS';
		}

		// Sum up!
		if ( $wp_discloses ) {
			// bad
			$this->add_message( 201, array( wp_sprintf_l( '%l', $wp_discloses ) ) );
		}

		// Readme file.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 202 );
			}

		} else {
			// warning
			$this->add_message( 101 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_nginx, $is_iis7;

		$wp_version  = get_bloginfo( 'version' );
		$php_version = phpversion();

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag + php header.
		if ( $has_response ) {

			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );

			// PHP version in headers.
			if ( false !== strpos( $powered_by, $php_version ) ) {

				if ( $is_nginx ) {
					$this->add_fix_message( 300 );
				} elseif ( $is_iis7 ) {
					$this->add_fix_message( 301 ); //// iis7_url_rewrite_rules ?
				} elseif ( ! $is_apache ) {
					$this->add_fix_message( 302 );
				} else {
					// .htaccess
					$rules  = "ServerSignature Off\n";
					$rules .= "<IfModule mod_headers.c>\n    Header unset X-Powered-By\n</IfModule>";

					if ( secupress_write_htaccess( 'php_version_disclose', $rules ) ) {

						// good
						$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );

						// Test our rule works.
						$response_test = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );

						if ( ! is_wp_error( $response_test ) && 200 === wp_remote_retrieve_response_code( $response_test ) ) {

							$powered_by = wp_remote_retrieve_header( $response_test, 'x-powered-by' );

							if ( false !== strpos( $powered_by, $php_version ) ) {
								// good
								secupress_activate_submodule( 'discloses', 'php-version' );
								$this->add_fix_message( 2, array( '<code>.htaccess</code>' ) );
							}
						}

					} else {
						// cantfix
						$this->add_fix_message( 303, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress php_version_disclose\n$rules\n# END SecuPress</pre>" ) );
					}
				}

			}

			// WordPress version in meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( count( array_filter( $matches ) ) ) {
				// good
				secupress_activate_submodule( 'discloses', 'generator' );
				$this->add_fix_message( 3 );
			}

		} else {
			// warning
			$this->add_fix_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wp-version-css' );
			$this->add_fix_message( 4 );
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wp-version-js' );
			$this->add_fix_message( 5 );
		}

		// Readme file.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {

				if ( $is_nginx ) {
					$this->add_fix_message( 300 );
				} elseif ( $is_iis7 ) {
					$this->add_fix_message( 301 ); //// iis7_url_rewrite_rules ?
				} elseif ( ! $is_apache ) {
					$this->add_fix_message( 302 );
				} else {
					// .htaccess
					$rules = "<files readme.html>\n    deny from all\n</files>";

					if ( secupress_write_htaccess( 'readme_version_disclose', $rules ) ) {
						// good
						$this->add_fix_message( 6, array( '<code>readme.html</code>', '<code>.htaccess</code>' ) );
					} else {
						// cantfix
						$this->add_fix_message( 303, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress readme_version_disclose\n$rules\n# END SecuPress</pre>" ) );
					}
				}
			}

		} else {
			// warning
			$this->add_fix_message( 101 );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
