<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


add_filter( 'pre_wp_update_https_detection_errors', 'secupress_update_https_detection_errors' );
/**
 * Just for our scanner, do not use wp_is_local_html_output() which is crazy bad.
 *
 * @since 2.0.1
 * @author Julio Potier
 *
 * @return (WP_Error)
 **/
function secupress_update_https_detection_errors() {
	$support_errors = new WP_Error();

	$response = wp_remote_request(
		home_url( '/', 'https' ),
		array(
			'headers'   => array(
				'Cache-Control' => 'no-cache',
			),
			'sslverify' => true,
		)
	);

	if ( is_wp_error( $response ) ) {
		$unverified_response = wp_remote_request(
			home_url( '/', 'https' ),
			array(
				'headers'   => array(
					'Cache-Control' => 'no-cache',
				),
				'sslverify' => false,
			)
		);

		if ( is_wp_error( $unverified_response ) ) {
			$support_errors->add(
				'https_request_failed',
				__( 'HTTPS request failed.' )
			);
		} else {
			$support_errors->add(
				'ssl_verification_failed',
				__( 'SSL verification failed.' )
			);
		}

		$response = $unverified_response;
	}

	if ( ! is_wp_error( $response ) ) {
		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$support_errors->add( 'bad_response_code', wp_remote_retrieve_response_message( $response ) );
		}
	}

	/**
	* Filter the returned errors
	*
	* @since 2.0.3
	* @author Julio Potier
	* @param (WP_Error) $support_errors
	* @param (WP_HTTP) $response
	* @return (WP_Error) $support_errors
	*/
	$support_errors = apply_filters( 'secupress.https_detection_errors', $support_errors, $response );
	return $support_errors;
}


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
	const VERSION = '2.0';


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
	protected $fixable = true;

	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your website is using an active HTTPS connection.', 'secupress' );
		$this->more     = __( 'An HTTPS connection is needed for many features on the web today, it also gains the trust of your visitors by helping to protecting their online privacy.', 'secupress' );
		$this->more_fix = static::get_messages( 301 );
		if ( false === $this->need_fix() ) {
			// "bad"
			$this->more_fix = static::get_messages( 300 );
			$this->fixable  = false;
		}
		if ( 0 === $this->need_fix() ) {
			// "plugin active"
			$this->more_fix = static::get_messages( 302 );
		}
		if ( -1 === $this->need_fix() ) {
			// "capa"
			$this->more_fix = static::get_messages( 303 );
		}
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
			200 => __( 'Your site is not totally using HTTPS/SSL: %s', 'secupress' ),
			201 => __( 'Your site does not use HTTPS/SSL. Error: %s', 'secupress' ),
			202   => __( 'Your website seems to run under maintenance mode, relaunch the HTTPS scanner later when you set it off.', 'secupress' ),
			// "cantfix"
			300 => __( 'Cannot be fixed automatically. You have to contact you host provider to ask him to <strong>upgrade your site with HTTPS/SSL</strong>.', 'secupress' ),
			301 => __( 'Update your HOME url and SITE url with <code>https://</code>.', 'secupress' ),
			302 => __( 'The module <strong>WordPress Core > Locations</strong> is activated, deactivate it to fix this.', 'secupress' ),
			303 => __( 'Sorry, you are not allowed to update this site to HTTPS.', 'secupress' ),
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
		return __( 'https://docs.secupress.me/article/171-connection-https-ssl-scan', 'secupress' );
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
		delete_option( 'https_detection_errors' );
		delete_transient( 'secupress_is_https_supported' );
		$supports_https = secupress_wp_version_is( '5.7' ) ? wp_is_https_supported() : true; // if not detectable, let's say it is.
		if ( ! $supports_https ) {
			// very bad
			$error = (array) get_option( 'https_detection_errors' );
			if ( isset( $error['bad_response_code'] ) && 'Service Unavailable' === reset( $error['bad_response_code'] ) ) {
				$this->add_message( 202 );
			} else {
				$this->add_message( 201, reset( $error ) );
			}
		} elseif ( ! secupress_site_is_using_https() ) {
			$bad   = [];
			$bad[] = secupress_site_is_using_https( 'home' ) ? '' : __( 'your front-end site is not using HTTPS', 'secupress' );
			$bad[] = secupress_site_is_using_https( 'site' ) ? '' : __( 'your back-end site is not using HTTPS', 'secupress' );
			$bad   = array_filter( $bad );
			$bad   = ucfirst( wp_sprintf_l( '%l', $bad ) ) . '.';
			// bad
			$this->add_message( 200, array( $bad ) );
		}
		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Tell if we need to rename the table prefix.
	 *
	 * @since 2.0 secupress_site_is_using_https() secupress_is_https_supported()
	 * @author Julio Potier
	 * @since 1.1.1
	 * @author Grégory Viguier
	 *
	 * @return (bool)
	 */
	protected function need_fix() {
		if ( ! current_user_can( 'update_https' ) ) {
			return -1;
		}
		if ( ! secupress_is_https_supported() ) {
			return false;
		}
		if ( secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-locations' ) ) {
			return 0;
		}
	}


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 2.0
	 *
	 * @return (array) The fix results.
	 */
	public function need_manual_fix() {
		return [ 'fix' => 'fix' ];
	}

	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 2.0
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return [ 'fix' => '&nbsp;' ];
	}

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 2.0 secupress_update_urls_to_https()
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {

		if ( false === $this->need_fix() ) {
			// "bad"
			$this->add_fix_message( 300 );
			return parent::fix();
		}
		if ( 0 === $this->need_fix() ) {
			// "plugin active"
			$this->add_fix_message( 302 );
			return parent::fix();
		}
		if ( -1 === $this->need_fix() ) {
			// "capa"
			$this->add_fix_message( 303 );
			return parent::fix();
		}

		secupress_update_urls_to_https();

		$this->add_fix_message( 0 );

		return parent::fix();
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 2.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		// Make the tests again, we want to be sure to not run this script unnecessarily.
		if ( false === $this->need_fix() ) {
			// "bad"
			$this->add_fix_message( 300 );
			return parent::manual_fix();
		}
		if ( 0 === $this->need_fix() ) {
			// "plugin active"
			$this->add_fix_message( 302 );
			return parent::manual_fix();
		}
		if ( -1 === $this->need_fix() ) {
			// "capa"
			$this->add_fix_message( 303 );
			return parent::manual_fix();
		}

		secupress_update_urls_to_https();

		$this->add_fix_message( 0 );

		return parent::manual_fix();
	}
}
