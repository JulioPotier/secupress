<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * WPML version disclose scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Wpml_Discloses extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		/** Translators: %s is a plugin name. */
		$this->title    = sprintf( __( 'Check if the %s plugin discloses its version.', 'secupress' ), 'WPML' );
		$this->more     = __( 'When an attacker wants to hack into a WordPress site, they will search for all available informations. The goal is to find something useful that will help him penetrate your site. Don’t let them easily find any informations.', 'secupress' );
		$this->more_fix = sprintf(
			/** Translators: 1 is a plugin name, 2 is the name of a protection, 3 is the name of a module. */
			__( 'Hide the %1$s version to prevent giving too much information to attackers. The %2$s protection from the module %3$s will be activated.', 'secupress' ),
			'WPML',
			'<strong>' . __( 'Plugin version disclosure', 'secupress' ) . '</strong>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) ) . '#row-content-protect_plugin-version-discloses">' . __( 'Sensitive Data', 'secupress' ) . '</a>'
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
			'<strong>' . __( 'Plugin version disclosure', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) ) . '#row-content-protect_plugin-version-discloses">' . __( 'Sensitive Data', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			/** Translators: %s is a plugin name. */
			0   => sprintf( __( 'The %s plugin does not reveal sensitive information.', 'secupress' ), '<strong>WPML</strong>' ),
			// "warning"
			/** Translators: %s is a plugin name. */
			100 => sprintf( __( 'Unable to determine if %s is disclosing its version on your homepage.', 'secupress' ), '<strong>WPML</strong>' ) . ' ' . $activate_protection_message,
			// "bad"
			/** Translators: 1 is a plugin name, 2 is some related info. */
			200 => sprintf( __( 'The %1$s plugin displays its version in the source code of your homepage (%2$s).', 'secupress' ), '<strong>WPML</strong>', '%s' ),
			// DEPRECATED, NOT IN USE ANYMORE.
			1   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			/** Translators: %s is a plugin name. */
			2   => sprintf( __( 'The %s’s version should be removed from your styles URLs now.', 'secupress' ), 'WPML' ),
			/** Translators: %s is a plugin name. */
			3   => sprintf( __( 'The %s’s version should be removed from your scripts URLs now.', 'secupress' ), 'WPML' ),
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
		return __( 'https://docs.secupress.me/article/104-wpml-version-number-disclosure-scan', 'secupress' );
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

		$discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), $this->get_default_request_args() );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag.
		if ( $has_response ) {
			$body = wp_remote_retrieve_body( $response );

			// WPML version in meta tag.
			preg_match_all( '#<meta name="generator" content="WPML [^"]*' . ICL_SITEPRESS_VERSION . '[^"]*"[^>]*>#s', $body, $matches );

			if ( array_filter( $matches ) ) {
				// "bad"
				$discloses[] = 'META';
			}
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . ICL_SITEPRESS_VERSION );

		/** This filter is documented in wp-includes/class.wp-styles.php */
		if ( apply_filters( 'style_loader_src', $style_url, 'secupress' ) === $style_url ) {
			// "bad"
			$discloses[] = 'CSS';
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . ICL_SITEPRESS_VERSION );

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
		// Activate.
		secupress_activate_submodule( 'discloses', 'wpml-version' );

		// "good"
		$this->add_fix_message( 0 );

		return parent::fix();
	}
}
