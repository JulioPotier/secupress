<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * WPOrg scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_WPOrg extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		$this->title    = __( 'Check if your installation can communicate with WordPress.org.', 'secupress' );
		$this->more     = __( 'Communicating with the WordPress servers is used to check for new versions, and to both install and update WordPress core, themes or plugins.' );
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
		$versions = secupress_get_php_versions();
		$messages = array(
			// "good"
			0   => __( 'Your site can communicate with WordPress.org.', 'secupress' ),
			// "bad"
			200   => __( 'Your site could not reach WordPress.org.', 'secupress' ),
			// "cantfix"
			300 => sprintf(
				'<p><a href="%s" target="_blank" rel="noopener noreferrer">%s <span class="screen-reader-text">%s</span><span aria-hidden="true" class="dashicons dashicons-external"></span></a></p>',
				/* translators: Localized Support reference. */
				esc_url( __( 'https://wordpress.org/support' ) ),
				__( 'Get help resolving this issue.', 'secupress' ),
				/* translators: accessibility text */
				__( '(opens in a new tab)' )
			)
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
		return __( 'https://docs.secupress.me/article/177-communicate-with-wordpress-org-or-secupress-me', 'secupress' );
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

		$wp_dotorg = wp_remote_get( 'https://api.wordpress.org', $this->get_default_request_args() );

		if ( ! is_wp_error( $wp_dotorg ) ) {
			$this->add_message( 0 );
		} else {
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
		$this->add_fix_message( 300 );
		return parent::fix();
	}

}
