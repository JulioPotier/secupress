<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad User Agent scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_User_Agent extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	public    static $prio    = 'high';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected static function init() {
		self::$type     = 'WordPress';
		self::$title    = __( 'Check if bad User Agents can visit your website.', 'secupress' );
		self::$more     = __( 'Bad User-Agents are bots that provide no value to the website. It includes scrapers, spambots, email harvesters and more bots that you don\'t want on your site. In any cases, those bots that are crawling with a malicious purpose, have no desire to follow any <code>robots.txt</code> or meta tag.', 'secupress' );
		self::$more_fix = sprintf(
			__( 'This will activate the option %1$s from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Bad User-Agents', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_user-agents-header">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
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
			0   => __( 'You are currently blocking Bad User Agents.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// "bad"
			200 => __( 'Your website should block <code>HTTP</code> requests for <strong>bad User Agents</strong>.', 'secupress' ),
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

		$response = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0, 'user-agent' => '<script>' ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$this->add_message( 200 );
			} else {
				// "good"
				$this->add_message( 0 );
			}
		} else {
			// "warning"
			$this->add_message( 100 );
		}

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

		// Activate.
		secupress_activate_submodule( 'firewall', 'user-agents-header' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
