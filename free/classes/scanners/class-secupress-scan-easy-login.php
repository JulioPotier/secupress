<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Easy Login scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Easy_Login extends SecuPress_Scan implements SecuPress_Scan_Interface {

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

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = 'pro';


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your login page is protected by double authentication.', 'secupress' );
		$this->more     = __( 'The login vector is often use in web attacks, every hour your website is the target of random bots whom try to log in your site. Adding another layer of login can improve the security.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the <strong>%1$s</strong> from the module %2$s.', 'secupress' ),
			__( 'PasswordLess Double Authentication', 'secupress' ),
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-double-auth_type">' . __( 'Users & Login', 'secupress' ) . '</a>'
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
			0   => __( 'The login page is protected by double authentication with %s.', 'secupress' ),
			1   => __( 'The <strong>PasswordLess Double Authentication</strong> module has been activated for every role. Users will receive an email to log-in now.', 'secupress' ),
			// "bad"
			200 => __( 'Your login system is <strong>not strong enough</strong>, you need a <strong>double authentication system</strong>.', 'secupress' ),
			201 => sprintf( __( 'Our module %s could fix this.', 'secupress' ), '<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-double-auth_type">' . __( 'PasswordLess', 'secupress' ) . '</a>' ),
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
		return __( 'https://docs.secupress.me/article/128-two-factor-authentication-scan', 'secupress' );
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

		$activated = secupress_is_submodule_active( 'users-login', 'passwordless' ) ? 'PasswordLess' : false;

		/**
		 * Overwrite the activated bool to force a good information
		 *
		 * @since 1.4
		 *
		 * @param (bool|string) False if not activated, string containing the plugin/system name than activate the feature
		 */

		$activated = apply_filters( 'secupress.scan.' . __CLASS__ . '.activated', $activated );

		if ( ! $activated ) {
			// "bad"
			$this->add_message( 200 );
			$this->add_pre_fix_message( 201 );
		} else {
			// "good"
			$this->add_message( 0, array( '<strong>' . $activated . '</strong>' ) );
		}

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
		secupress_activate_submodule( 'users-login', 'passwordless' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
