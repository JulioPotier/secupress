<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Anti Scanner scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Anti_Scanner extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if automated scanner can target your website.', 'secupress' );
		self::$more  = __( 'Automated scanner requires a triple page reload to be identical regarding contents. By giving them a different content for each request, it will not be possible for it to work properly.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'You are currently blocking <strong>automated scanning</strong>.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// bad
			200 => __( 'Your website should block <strong>automated scanning</strong>.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// Scanners and Breach
		$hashes = array();

		for ( $i = 0 ; $i < 3 ; ++$i ) {
			$response = wp_remote_get( user_trailingslashit( home_url() ) . '?' . uniqid( 'time=', true ), array( 'redirection' => 0 ) );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$hashes[] = md5( wp_remote_retrieve_body( $response ) );
			}
		}

		$hashes = count( array_unique( $hashes ) );

		if ( 3 === $hashes ) {
			// good
			$this->add_message( 0 );

		} elseif ( 0 === $hashes ) {
			// warning
			$this->add_message( 100 );

		} else {
			// bad
			$this->add_message( 200 );

		}

		return parent::scan();
	}


	public function fix() {

		$settings = array( 'bbq-url-content_bad-sqli-scan' => '1' );
		secupress_activate_module( 'firewall', $settings );

		$this->add_fix_message( 0 );

		return parent::fix();
	}
}
