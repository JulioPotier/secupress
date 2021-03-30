<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Subscription scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Subscription extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.3';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;
	/**
	 * The minimum role to be available here
	 *
	 * @var (string)
	 */
	protected $role_minimum;
	/**
	 * The minimum role, translated
	 *
	 * @var (string)
	 */
	protected $role_minimum_i18n;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		global $wp_roles;
		$this->role_minimum      = apply_filters( 'secupress.scan.' . __CLASS__ . '.role_minimum', 'subscriber' );
		$this->role_minimum_i18n = isset( $wp_roles->role_names[ $this->role_minimum ] ) ? translate_user_role( $wp_roles->role_names[ $this->role_minimum ] ) : _x( 'None', 'a WP role', 'secupress' );
		$this->title             = __( 'Check if the subscription settings are set correctly.', 'secupress' );

		if ( ! is_multisite() || is_network_admin() ) {
			$this->more     = sprintf( __( 'If user registrations are open, the default user role should be %s. Moreover, your registration page should be protected from bots.', 'secupress' ), $this->role_minimum_i18n );
			$this->more_fix = sprintf(
				__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
				'<em>' . __( 'Use a Captcha for everyone', 'secupress' ) . '</em>',
				'<a href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-captcha_activate">' . __( 'Users & Login', 'secupress' ) . '</a>'
			);

			if ( is_network_admin() ) {
				$this->more_fix .= '<br/>' . sprintf( __( 'If the default user role is not %1$s in some of your websites, administrators will be asked to set the default user role to %1$s.', 'secupress' ), $this->role_minimum_i18n );
			} else {
				$this->more_fix .= '<br/>' . sprintf( __( 'Set the default user’s role to %s.', 'secupress' ), $this->role_minimum_i18n );
			}
		} else {
			$this->more     = sprintf( __( 'If user registrations are open, the default user role should be %s.', 'secupress' ), $this->role_minimum_i18n );
			$this->more_fix = sprintf( __( 'Set the default user’s role to %s.', 'secupress' ), $this->role_minimum_i18n );
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
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Use a Captcha for everyone', 'secupress' ) . '</strong>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'users-login' ) ) . '#row-captcha_activate">' . __( 'Users & Login', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			0   => __( 'Your subscription settings are set correctly.', 'secupress' ),
			1   => __( 'A captcha module has been activated to block bot registration.', 'secupress' ),
			2   => __( 'The user role for new registrations has been set to <strong>%s</strong>.', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine the status of your subscription settings.', 'secupress' ) . ' ' . $activate_protection_message,
			/** Translators: %s is the plugin name. */
			101 => sprintf( __( 'You have a big network, %s must work on some data before being able to perform this scan.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
			// "bad"
			200 => __( 'The default role in your installation is <strong>%1$s</strong> and it should be <strong>%2$s</strong>, or registrations should be <strong>closed</strong>.', 'secupress' ),
			201 => __( 'The registration page is <strong>not protected</strong> from bots.', 'secupress' ),
			202 => _n_noop( 'The default role is not %2$s in %1$s of your sites.', 'The default role is not %2$s in %1$s of your sites.', 'secupress' ),
			// "cantfix"
			/** Translators: %s is the plugin name. */
			300 => sprintf( __( 'The default role cannot be fixed from here. A new %s menu item has been activated in the relevant site’s administration area.', 'secupress' ), '<strong>' . SECUPRESS_PLUGIN_NAME . '</strong>' ),
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
		return __( 'https://docs.secupress.me/article/134-membership-settings-scan', 'secupress' );
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

		global $wp_roles;

		// Subscriptions are closed.
		if ( ! secupress_users_can_register() ) {
			// "good"
			$this->add_message( 0 );
			return parent::scan();
		}

		if ( ! static::are_centralized_blog_options_filled() ) {
			// "warning"
			$this->add_message( 101 );
			return parent::scan();
		}

		// Default role.
		if ( $this->is_network_admin() ) {
			$roles = get_site_option( 'secupress_default_role' );
			$blogs = array();

			foreach ( $roles as $blog_id => $role ) {
				if ( 'administrator' === $role ) {
					$blogs[] = $blog_id;
				}
			}

			if ( $count = count( $blogs ) ) {
				// "bad"
				$this->add_message( 202, array( $count, $count, $this->role_minimum_i18n ) );
			}
		} else {
			$role = get_option( 'default_role' );

			if ( 'administrator' === $role ) {
				// "bad"
				$role = isset( $wp_roles->role_names[ $role ] ) ? translate_user_role( $wp_roles->role_names[ $role ] ) : _x( 'None', 'a WP role', 'secupress' );
				$this->add_message( 200, array( $role, $this->role_minimum_i18n ) );
			}
		}

		// Bots.
		$token        = wp_generate_password();
		set_transient( 'secupress_scan_subscription_token', $token );
		$user_login   = 'secupress_' . time();
		$request_args = $this->get_default_request_args();
		$request_args = array_merge( $request_args, array(
			'body' => array(
				'user_login'      => $user_login,
				'user_email'      => 'secupress_no_mail_SS@fakemail.' . time(),
				'secupress_token' => $token,
			),
		) );
		unset( $request_args['cookies'] );
		$response     = wp_remote_post( wp_registration_url(), $request_args );

		delete_transient( 'secupress_scan_subscription_token' );

		if ( ! is_wp_error( $response ) ) {

			if ( $user_id = username_exists( $user_login ) ) {

				wp_delete_user( $user_id );

				if ( 'failed' === get_transient( 'secupress_registration_test' ) ) {
					// "bad"
					$this->add_message( 201 );
				}
			}
		}

		delete_transient( 'secupress_registration_test' );

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
		if ( is_multisite() ) {
			$this->add_fix_message( 300 );
		} else {
			$this->add_fix_message( 2, array( $this->role_minimum_i18n ) );
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
		global $wp_roles;

		if ( ! secupress_users_can_register() ) {
			return parent::fix();
		}

		// Default role.
		if ( $this->is_network_admin() ) {

			$roles  = get_site_option( 'secupress_default_role' );
			$is_bad = false;

			foreach ( $roles as $blog_id => $role ) {
				if ( 'administrator' === $role ) {
					$is_bad = true;
					$role   = isset( $wp_roles->role_names[ $role ] ) ? translate_user_role( $wp_roles->role_names[ $role ] ) : _x( 'None', 'a WP role', 'secupress' );
					$data   = array( $role, $this->role_minimum_i18n );
					// Add a scan message for each sub-site with wrong role.
					$this->add_subsite_message( 200, $data, 'scan', $blog_id );
				} else {
					$this->set_empty_data_for_subsite( $blog_id );
				}
			}

			if ( $is_bad ) {
				// "cantfix"
				$this->add_fix_message( 300 );
			}
		} elseif ( 'administrator' === get_option( 'default_role' ) ) {
			update_option( 'default_role', $this->role_minimum );
			// "good"
			$this->add_fix_message( 2 );
		}

		// Bots: use a captcha.
		secupress_activate_submodule( 'users-login', 'login-captcha' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
