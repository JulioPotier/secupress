<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * HTTPS scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_HTTPS extends SecuPress_Scan implements SecuPress_Scan_Interface {

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

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = false;

	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your website is using an active HTTPS connection.', 'secupress' );
		$this->more     = __( 'An HTTPS connection is needed for many features on the web today, it also gains the trust of your visitors by helping to protecting their online privacy.' );
		$this->more_fix = static::get_messages( 300 );
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
			0   => __( 'Your website is using an active HTTPS/SSL connection.', 'secupress' ),
			// "bad"
			200 => __( 'Only parts of your site are using HTTPS/SSL: %s', 'secupress' ),
			201 => __( 'Your site does not use HTTPS/SSL. Talk to your web host about OpenSSL support for PHP and HTTPS.', 'secupress' ),
			// "cantfix"
			300 => __( 'Cannot be fixed automatically. You have to contact you host provider to ask him to <strong>upgrade your site with HTTPS/SSL</strong>.', 'secupress' ),
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
		return __( 'http://docs.secupress.me/article/99-database-table-prefix-scan', 'secupress' ); ////
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

		if ( is_ssl() ) {
			$wp_url         = get_bloginfo( 'wpurl' );
			$site_url       = get_bloginfo( 'url' );
			$supports_https = wp_http_supports( array( 'ssl' ) );

			if ( ! $supports_https || 'https' !== substr( $wp_url, 0, 5 ) || 'https' !== substr( $site_url, 0, 5 ) ) {
				$bad   = [];
				$bad[] = ! $supports_https ? __( 'your site is not using PHP OpenSSL', 'secupress' ) : '';
				$bad[] = 'https' !== substr( $wp_url, 0, 5 ) ? __( 'your front-end site is not using HTTPS', 'secupress' ) : '';
				$bad[] = 'https' !== substr( $site_url, 0, 5 ) ? __( 'your back-end site is not using HTTPS', 'secupress' ) : '';
				$bad   = array_filter( $bad );
				$bad   = ucfirst( wp_sprintf_l( '%l', $bad ) ) . '.';
				// bad
				$this->add_message( 200, $bad );
			}
		} else {
			// very bad
			$this->add_message( 201 );
		}
			// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Tell if we need to rename the table prefix.
	 *
	 * @since 1.1.1
	 * @author Grégory Viguier
	 *
	 * @return (bool)
	 */
	protected function need_fix() {
		$this->add_fix_message( 300 );
		return parent::fix();
	}

}
