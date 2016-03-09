<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Long URL scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Block_Long_URL extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = sprintf( __( 'Check if long URL can reach your website (more than %s chars).', 'secupress' ), number_format_i18n( apply_filters( 'secupress.plugin.len.bad-url-length', 300 ) ) );
		self::$more     = sprintf( __( 'A usual URL has no more than %s characters, but attackers often need to test very long strings when they try to hack something.', 'secupress' ), number_format_i18n( apply_filters( 'secupress.plugin.len.bad-url-length', 300 ) ) );
		self::$more_fix = sprintf(
			__( 'This will activate the option %1$s from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Long URLs', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#Block_Long_URLs">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently blocking too long string requests.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => __( 'Your website should block <strong>too long string requests</strong>.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$test_len = apply_filters( 'secupress.plugin.len.bad-url-length', 300 );
		$response = wp_remote_get( user_trailingslashit( home_url() ) . '?' . time() . '=' . wp_generate_password( $test_len, false ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 200 );
			} else {
				// good
				$this->add_message( 0 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		return parent::scan();
	}


	public function fix() {

		// Activate.
		secupress_activate_submodule( 'firewall', 'bad-url-length' );

		// good
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
