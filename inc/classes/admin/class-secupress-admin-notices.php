<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Admin notices class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Admin_Notices extends SecuPress_Singleton {

	const VERSION   = '1.0';
	const META_NAME = 'dismissed_secupress_notices';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	/**
	 * @var Will store the notices.
	 */
	protected        $notices  = array();
	/**
	 * @var Tell if the css styles have been enqueued and prevent to do it twice.
	 */
	protected static $done_css = false;
	/**
	 * @var Tell if the js scripts have been enqueued and prevent to do it twice.
	 */
	protected static $done_js  = false;
	/**
	 * @var ".min" suffix to add (or not) to the css/js file name.
	 */
	protected static $suffix;
	/**
	 * @var Version to use for the css/js files.
	 */
	protected static $version;


	// Public methods ==============================================================================

	/**
	 * Add an admin notice.
	 *
	 * @since 1.0
	 *
	 * @param (string)      $message    The message to display in the notice.
	 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
	 * @param (string|bool) $notice_id  A unique identifier to tell id the notice is dismissible.
	 *                                  false: the notice is not dismissible.
	 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
	 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
	 */
	public function add( $message, $error_code = 'updated', $notice_id = false ) {
		if ( false !== $notice_id ) {
			if ( $notice_id && self::is_dismissed( $notice_id ) ) {
				return;
			}
			// Add notices script.
			self::_enqueue_script();
		}

		// Add notices style.
		self::_enqueue_style();

		$error_code = 'error' === $error_code ? 'error' : 'updated';
		$notice_id  = $notice_id ? sanitize_title( $notice_id ) : $notice_id;

		if ( ! isset( $this->notices[ $error_code ] ) ) {
			$this->notices[ $error_code ] = array(
				'permanent'      => array(),
				'wp-dismissible' => array(),
				'sp-dismissible' => array(),
			);
		}
		if ( false === $notice_id ) {
			// The notice is not dismissible.
			$this->notices[ $error_code ]['permanent'][] = $message;
		} elseif ( $notice_id ) {
			// The notice is dismissible, with a custom ajax call.
			$this->notices[ $error_code ]['sp-dismissible'][ $notice_id ] = $message;
		} else {
			// The notice is dismissible.
			$this->notices[ $error_code ]['wp-dismissible'][] = $message;
		}

	}

	/**
	 * Add a temporary admin notice.
	 *
	 * @since 1.0
	 *
	 * @param (string)      $message    The message to display in the notice.
	 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
	 */
	public function add_temporary( $message, $error_code = 'updated' ) {
		$error_code = 'error' === $error_code ? 'error' : 'updated';
		$notices    = secupress_get_transient( 'secupress-notices-' . get_current_user_id() );
		$notices    = is_array( $notices ) ? $notices : array();
		$notices[]  = compact( 'message', 'error_code' );

		secupress_set_transient( 'secupress-notices-' . get_current_user_id(), $notices );

	}


	/**
	 * Dismiss a notice for a user: a user meta is added to keep track of the "dismissed" state.
	 *
	 * @since 1.0
	 *
	 * @param (string) $notice_id The notice identifier.
	 * @param (int)    $user_id   User ID. If not set, fallback to the current user ID.
	 *
	 * @return (bool) true on success.
	 */
	public static function dismiss( $notice_id, $user_id = 0 ) {
		$notice_id  = $notice_id ? sanitize_title( $notice_id ) : $notice_id;

		if ( ! $notice_id ) {
			return false;
		}

		$user_id   = $user_id ? absint( $user_id ) : get_current_user_id();
		$dismissed = (string) get_user_option( self::META_NAME, $user_id );
		$dismissed = ',' . $dismissed . ',';

		if ( false === strpos( $dismissed, ',' . $notice_id . ',' ) ) {
			$dismissed = trim( $dismissed . $notice_id, ',' );
			$dismissed = str_replace( ',,', ',', $dismissed );
			update_user_option( $user_id, self::META_NAME, $dismissed );
			return true;
		}

		return false;
	}


	/**
	 * "Undismiss" a notice for a user: the notice is removed from the user meta.
	 *
	 * @since 1.0
	 *
	 * @param (string) $notice_id The notice identifier.
	 * @param (int)    $user_id   User ID.
	 */
	public static function reinit( $notice_id, $user_id = 0 ) {
		$notice_id  = $notice_id ? sanitize_title( $notice_id ) : $notice_id;

		if ( ! $notice_id ) {
			return;
		}

		$user_id   = $user_id ? absint( $user_id ) : get_current_user_id();
		$dismissed = (string) get_user_option( self::META_NAME, $user_id );
		$dismissed = ',' . $dismissed . ',';
		$notice_id = ',' . $notice_id . ',';

		if ( false !== strpos( $dismissed, $notice_id ) ) {
			$dismissed = str_replace( array( $notice_id, ',,' ), ',', $dismissed );
			$dismissed = trim( $dismissed, ',' );

			if ( '' === $dismissed ) {
				delete_user_option( $user_id, self::META_NAME );
			} else {
				update_user_option( $user_id, self::META_NAME, $dismissed );
			}
		}
	}


	/**
	 * Tell if a notice is dismissed.
	 *
	 * @since 1.0
	 *
	 * @param (string) $notice_id The notice identifier.
	 *
	 * @return (bool|null) true if dismissed, false if not, null if the notice is not dismissible.
	 */
	public static function is_dismissed( $notice_id ) {
		if ( $notice_id ) {
			// Get dismissed notices.
			$dismissed = explode( ',', (string) get_user_option( self::META_NAME, get_current_user_id() ) );
			$dismissed = array_flip( $dismissed );

			return isset( $dismissed[ $notice_id ] );
		}
		return null;
	}


	// Private methods =============================================================================

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		self::$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
		self::$version = self::$suffix ? SECUPRESS_VERSION : time();

		add_action( 'all_admin_notices',                   array( $this, '_print' ), 20 );
		add_action( 'wp_ajax_secupress_dismiss-notice',    array( __CLASS__, '_ajax_dismiss' ) );
		add_action( 'admin_post_secupress_dismiss-notice', array( __CLASS__, '_admin_dismiss' ) );
	}


	/**
	 * Enqueue JS scripts.
	 *
	 * @since 1.0
	 */
	protected static function _enqueue_script() {
		if ( self::$done_js ) {
			return;
		}
		self::$done_js = true;

		wp_enqueue_script( 'secupress-notices', SECUPRESS_ADMIN_JS_URL . 'secupress-notices' . self::$suffix . '.js', array( 'jquery' ), self::$version, true );
		wp_localize_script( 'secupress-notices', 'SecuPressi18nNotices', array(
			'dismiss' => __( 'Dismiss', 'secupress' ),
			'nonce'   => wp_create_nonce( 'secupress-notices' ),
		) );

	}


	/**
	 * Enqueue CSS styles.
	 *
	 * @since 1.0
	 */
	protected static function _enqueue_style() {
		if ( self::$done_css ) {
			return;
		}
		self::$done_css = true;

		wp_enqueue_style( 'secupress-notices', SECUPRESS_ADMIN_CSS_URL . 'secupress-notices' . self::$suffix . '.css', array(), self::$version );

	}


	/**
	 * Display the notices.
	 *
	 * @since 1.0
	 *
	 * The notices are displayed by error code ("error" or "updated"), then by type (dismissible with state stored, dismissible like WP, not dismissible).
	 * All not dismissible ones are grouped into one notice. Same thing for the "dismissible like WP" ones.
	 * Only the "dismissible with state stored" are printed separately, so the user can dismiss some and not others.
	 */
	public function _print() {
		if ( ! $this->notices ) {
			return;
		}
		$compat  = secupress_wp_version_is( '4.2-beta4' ) ? '' : ' secupress-compat-notice';
		$referer = urlencode( esc_url( secupress_get_current_url( 'raw' ) ) );

		foreach ( $this->notices as $error_code => $types ) {
			$types = array_filter( $types, 'count' );

			if ( ! $types ) {
				continue;
			}

			foreach ( $types as $type => $messages ) {
				if ( 'sp-dismissible' === $type ) {
					foreach ( $messages as $notice_id => $message ) {
						$button = admin_url( 'admin-post.php?action=secupress_dismiss-notice&notice_id=' . $notice_id . '&_wp_http_referer=' . $referer );
						$button = wp_nonce_url( $button, 'secupress-notices' );
						$button = '<a href="' . $button . '" class="notice-dismiss"><span class="screen-reader-text">' . __( 'Dismiss', 'secupress' ) . '</span></a>';
						$message = strpos( $message, '<p>' ) === false ? '<p>' . $message . '</p>' : $message;
						?>
						<div class="<?php echo $error_code . $compat; ?> notice secupress-notice secupress-is-dismissible" data-id="<?php echo $notice_id; ?>">
							<?php echo $message; ?>
							<?php echo $button; ?>
						</div>
						<?php
					}
				} elseif ( 'wp-dismissible' === $type ) {
					?>
					<div class="<?php echo $error_code . $compat; ?> notice secupress-notice secupress-is-dismissible">
						<?php
						$message = implode( '<br class="separator"/>', $messages );
						echo strpos( $message, '<p>' ) === false ? '<p>' . $message . '</p>' : $message;
						?>
					</div>
					<?php
				} else {
					?>
					<div class="<?php echo $error_code; ?> notice secupress-notice">
						<?php
						$message = implode( '<br class="separator"/>', $messages );
						echo strpos( $message, '<p>' ) === false ? '<p>' . $message . '</p>' : $message;
						?>
					</div>
					<?php
				}
			}
		}
	}


	/**
	 * Ajax callback that stores the "dismissed" state.
	 *
	 * @since 1.0
	 *
	 * @return A json object.
	 */
	public static function _ajax_dismiss() {
		if ( empty( $_POST['notice_id'] ) ) {
			wp_die( -1 );
		}

		check_ajax_referer( 'secupress-notices' );

		/*
		 * Filter the capability needed to dismiss the notice.
		 *
		 * @since 1.0
		 *
		 * @param (string) Capability or user role.
		 * @param (string) The notice Identifier.
		 *
		 * @return (string) Capability or user role.
		 */
		$capability = apply_filters( 'secupress_ajax_dismiss_notice_capability', secupress_get_capability(), $_POST['notice_id'] );

		if ( ! current_user_can( $capability ) ) {
			wp_die( -1 );
		}

		if ( self::dismiss( $_POST['notice_id'] ) ) {
			wp_die( 1 );
		}
		wp_die( -1 );
	}


	/**
	 * Admin post callback that stores the "dismissed" state without JS.
	 *
	 * @since 1.0
	 */
	public static function _admin_dismiss() {
		if ( empty( $_GET['notice_id'] ) ) {
			wp_nonce_ays( '' );
		}

		check_admin_referer( 'secupress-notices' );

		/*
		 * Filter the capability needed to dismiss the notice.
		 *
		 * @since 1.0
		 *
		 * @param (string) Capability or user role.
		 * @param (string) The notice Identifier.
		 *
		 * @return (string) Capability or user role.
		 */
		$capability = apply_filters( 'secupress_ajax_dismiss_notice_capability', secupress_get_capability(), $_GET['notice_id'] );

		if ( ! current_user_can( $capability ) ) {
			wp_nonce_ays( '' );
		}

		if ( self::dismiss( $_GET['notice_id'] ) ) {
			wp_safe_redirect( wp_get_referer() );
			die();
		}
		wp_nonce_ays( '' );
	}

}
