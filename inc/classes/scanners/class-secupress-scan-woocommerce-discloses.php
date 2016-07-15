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
	public    static $prio    = 'medium';


	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		self::$type     = __( 'Plugins' );
		/* translators: %s is a plugin name */
		self::$title    = sprintf( __( 'Check if the %s plugin discloses its version.', 'secupress' ), 'WooCommerce' );
		self::$more     = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );
		/* translators: %s is a plugin name */
		$this->more_fix = sprintf( __( 'This will hide the %s version to avoid being read by attackers.', 'secupress' ), 'WooCommerce' );
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
			/* translators: %s is a plugin name */
			0   => sprintf( __( 'The %s plugin does not reveal sensitive informations.', 'secupress' ), 'WooCommerce' ),
			1   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			/* translators: %s is a plugin name */
			2   => sprintf( __( 'The %s\'s version should be removed from your styles URL now.', 'secupress' ), 'WooCommerce' ),
			/* translators: %s is a plugin name */
			3   => sprintf( __( 'The %s\'s version should be removed from your scripts URL now.', 'secupress' ), 'WooCommerce' ),
			// "warning"
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			// "bad"
			/* translators: 1 is a plugin name, 2 is some related info */
			200 => sprintf( __( 'The website displays the <strong>%1$s\'s version</strong> in the homepage source code (%2$s).', 'secupress' ), 'WooCommerce', '%s' ),
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

		$discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( add_query_arg( time(), time(), user_trailingslashit( home_url() ) ), array( 'redirection' => 0 ) );
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


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {

		// Get home page contents.
		$response     = wp_remote_get( add_query_arg( time(), time(), user_trailingslashit( home_url() ) ), array( 'redirection' => 0 ) );
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
