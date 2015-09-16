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
		self::$more  = __( 'When a attacker wants to hack into a WordPress site, he\'ll search for a maximum of information. The goal is to find outdated versions of your server softwares or WordPress component. Don\'t let them easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your site doesn\'t reveal sensitive informations.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			101 => sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), home_url( 'readme.html' ) ),
			// bad
			200 => __( 'The website displays the <strong>PHP version</strong> in the request headers.', 'secupress' ),
			201 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code (%s).', 'secupress' ),
			202 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code.', 'secupress' ),
			203 => sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), home_url( 'readme.html' ) ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$response     = wp_remote_get( home_url(), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$head = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body = wp_remote_retrieve_body( $response );
		} else {
			// warning
			$this->add_message( 100 );
		}

		// Generator meta tag + php header
		if ( $has_response ) {

			// PHP version in headers.
			if ( strpos( $head, phpversion() ) !== false ) {
				// bad
				$this->add_message( 200 );
			}

			// WordPress version in meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . get_bloginfo( 'version' ) . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( count( array_filter( $matches ) ) ) {
				// bad
				$this->add_message( 201, array( 'META' ) );
			}

		}

		// What about style tag src?
		if ( ! $this->has_status() ) {

			$style_url = home_url( '/fake.css?ver=' . get_bloginfo( 'version' ) );

			if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
				// bad
				$this->add_message( 201, array( 'CSS' ) );
			}

		}

		// What about script tag src?
		if ( ! $this->has_status() ) {

			$script_url = home_url( '/fake.js?ver=' . get_bloginfo( 'version' ) );

			if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
				// bad
				$this->add_message( 201, array( 'JS' ) );
			}

		}

		// What about full source page?
		if ( ! $this->has_status() && $has_response && strpos( $body, get_bloginfo( 'version' ) ) ) {
			// bad
			$this->add_message( 202 );
		}

		// Readme file.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 203 );
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

		// include the fix here.

		return parent::fix();
	}
}
