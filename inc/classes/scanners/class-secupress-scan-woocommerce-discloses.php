<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * WooCommerce version disclose scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Woocommerce_Discloses extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

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
		/** Translators: %s is a plugin name */
		$this->title    = sprintf( __( 'Check if the %s plugin discloses its version.', 'secupress' ), 'WooCommerce' );
		$this->more     = __( 'When an attacker wants to hack into a WordPress site, (s)he will search for all available informations. The goal is to find something useful that will help him penetrate your site. Don\'t let them easily find any informations.', 'secupress' );
		/** Translators: %s is a plugin name */
		$this->more_fix = sprintf( __( 'Hide the %s version to avoid being read by attackers.', 'secupress' ), 'WooCommerce' );
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
			/** Translators: %s is a plugin name */
			0   => sprintf( __( 'The %s plugin does not reveal sensitive information.', 'secupress' ), 'WooCommerce' ),
			1   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			/** Translators: %s is a plugin name */
			2   => sprintf( __( 'The %s\'s version should be removed from your styles URLs now.', 'secupress' ), 'WooCommerce' ),
			/** Translators: %s is a plugin name */
			3   => sprintf( __( 'The %s\'s version should be removed from your scripts URLs now.', 'secupress' ), 'WooCommerce' ),
			// "warning"
			100 => sprintf( __( 'Unable to determine if %s is disclosing its version on your homepage.', 'secupress' ), 'WooCommerce' ),
			// "bad"
			/** Translators: 1 is a plugin name, 2 is some related info */
			200 => sprintf( __( 'The %1$s plugin displays its version in the source code of your homepage (%2$s).', 'secupress' ), 'WooCommerce', '%s' ),
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
		$discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), array( 'redirection' => 0, 'timeout' => $this->get_timeout(), 'headers' => array( 'X-SecuPress-Origin' => __CLASS__ ) ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag.
		if ( $has_response ) {
			$body = wp_remote_retrieve_body( $response );

			// WPML version in meta tag.
			preg_match_all( '#<meta name="generator" content="WooCommerce [^"]*' . esc_attr( WC_VERSION ) . '[^"]*"[^>]*>#s', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "bad"
				$discloses[] = 'META';
			}
		} else {
			// "warning"
			$this->add_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . WC_VERSION );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "bad"
			$discloses[] = 'CSS';
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . WC_VERSION );

		/** This filter is documented in wp-includes/class.wp-scripts.php */
		if ( apply_filters( 'script_loader_src', $script_url, 'secupress' ) === $script_url ) {
			// "bad"
			$discloses[] = 'JS';
		}

		// Sum up!
		if ( $discloses ) {
			// "bad"
			$this->add_message( 200, array( $discloses ) );
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
		// Get home page contents.
		$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), array( 'redirection' => 0, 'timeout' => $this->get_timeout(), 'headers' => array( 'X-SecuPress-Origin' => __CLASS__ ) ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag.
		if ( $has_response ) {

			$body = wp_remote_retrieve_body( $response );

			// WPML version in meta tag.
			preg_match_all( '#<meta name="generator" content="WooCommerce [^"]*' . esc_attr( WC_VERSION ) . '[^"]*"[^>]*>#s', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "good"
				secupress_activate_submodule( 'discloses', 'woocommerce-generator' );
				$this->add_fix_message( 1 );
			}
		} else {
			// "warning"
			$this->add_fix_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . WC_VERSION );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "good"
			secupress_activate_submodule( 'discloses', 'woocommerce-version-css' );
			$this->add_fix_message( 2 );
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . WC_VERSION );

		/** This filter is documented in wp-includes/class.wp-scripts.php */
		if ( apply_filters( 'script_loader_src', $script_url, 'secupress' ) === $script_url ) {
			// "good"
			secupress_activate_submodule( 'discloses', 'woocommerce-version-js' );
			$this->add_fix_message( 3 );
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}
}
