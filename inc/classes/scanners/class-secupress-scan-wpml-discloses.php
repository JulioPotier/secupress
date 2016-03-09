<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * WpmlVersion scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Wpml_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = __( 'Plugins' );
		/* translators: %s is a plugin name */
		self::$title = sprintf( __( 'Check if the %s plugin discloses its version.', 'secupress' ), 'WPML' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );
		self::$more_fix = __( 'The fix will hide plugins version to avoid being read by attackers.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			/* translators: %s is a plugin name */
			0   => sprintf( __( 'The %s plugin does not reveal sensitive informations.', 'secupress' ), 'WPML' ),
			1   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			/* translators: %s is a plugin name */
			2   => sprintf( __( 'The %s\'s version should be removed from your styles URL now.', 'secupress' ), 'WPML' ),
			/* translators: %s is a plugin name */
			3   => sprintf( __( 'The %s\'s version should be removed from your scripts URL now.', 'secupress' ), 'WPML' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			/* translators: 1 is a plugin name, 2 is some related info */
			200 => sprintf( __( 'The website displays the <strong>%1$s\'s version</strong> in the homepage source code (%2$s).', 'secupress' ), 'WPML', '%s' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag.
		if ( $has_response ) {
			$body = wp_remote_retrieve_body( $response );

			// WPML version in meta tag.
			preg_match_all( '#<meta name="generator" content="WPML [^"]*' . ICL_SITEPRESS_VERSION . '[^"]*"[^>]*>#s', $body, $matches );

			if ( array_filter( $matches ) ) {
				// bad
				$discloses[] = 'META';
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . ICL_SITEPRESS_VERSION );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// bad
			$discloses[] = 'CSS';
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . ICL_SITEPRESS_VERSION );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// bad
			$discloses[] = 'JS';
		}

		// Sum up!
		if ( $discloses ) {
			// bad
			$this->add_message( 200, array( $discloses ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag
		if ( $has_response ) {

			$body = wp_remote_retrieve_body( $response );

			// WPML version in meta tag.
			preg_match_all( '#<meta name="generator" content="WPML [^"]*' . ICL_SITEPRESS_VERSION . '[^"]*"[^>]*>#s', $body, $matches );

			if ( array_filter( $matches ) ) {
				// good
				secupress_activate_submodule( 'discloses', 'wpml-generator' );
				$this->add_fix_message( 1 );
			}

		} else {
			// warning
			$this->add_fix_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . ICL_SITEPRESS_VERSION );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wpml-version-css' );
			$this->add_fix_message( 2 );
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . ICL_SITEPRESS_VERSION );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wpml-version-js' );
			$this->add_fix_message( 3 );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
