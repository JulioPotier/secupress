<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Anti Scanner scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Anti_Scanner extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.2';


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
		$this->title    = __( 'Check if automated bot scanners can target your website.', 'secupress' );
		$this->more     = __( 'Automated scanners require the contents of three page reloads to be identical. By showing them different content for each request, the scanner will not be possible for it to work properly.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Block SQLi Scan Attempts', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-url-content_bad-sqli-scan">' . __( 'Firewall', 'secupress' ) . '</a>'
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
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Block SQLi Scan Attempts', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-url-content_bad-sqli-scan">' . __( 'Firewall', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			0   => __( 'You are currently blocking <strong>automated scanning</strong>.', 'secupress' ),
			1   => __( 'Protection activated against <strong>automated scanning</strong>', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine if you are blocking <strong>automated scanning</strong>.', 'secupress' ) . ' ' . $activate_protection_message,
			// "bad"
			200 => __( 'Your website should block <strong>automated scanning</strong>.', 'secupress' ),
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
		return __( 'http://docs.secupress.me/article/111-anti-sqli-scanner-scan', 'secupress' );
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
		// Scanners and Breach.
		$hashes = array();

		for ( $i = 0 ; $i < 3 ; ++$i ) {
			$response = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), $this->get_default_request_args() );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				$hashes[] = md5( wp_remote_retrieve_body( $response ) );
			}
		}

		$hashes = array_values( array_flip( array_flip( $hashes ) ) );

		if ( isset( $hashes[2] ) ) { // = 3 different
			// "good"
			$this->add_message( 0 );

		} elseif ( ! isset( $hashes[0] ) ) { // = error during page request
			// "warning"
			$this->add_message( 100 );

		} else { // = we got 1 or 2 different hashes only.
			// "bad"
			$this->add_message( 200 );

		}

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
		// Activate.
		secupress_activate_submodule( 'firewall', 'bad-sqli-scan' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
