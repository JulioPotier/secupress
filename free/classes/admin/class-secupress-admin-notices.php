<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Admin notices class.
 *
 * @package SecuPress
 * 
 * @author Julio Potier
 * @since 1.3
 * 
 * @author Grégory Viguier
 * @since 1.0
 */
class SecuPress_Admin_Notices extends SecuPress_Singleton {

	const VERSION   = '1.1';
	const META_NAME = 'dismissed_secupress_notices';

	/**
	 * Singleton The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;
	/**
	 * Will store the notices.
	 *
	 * @var (array)
	 */
	protected        $notices  = array();
	/**
	 * Tell if the css styles have been enqueued and prevent to do it twice.
	 *
	 * @var (bool)
	 */
	protected static $done_css = false;
	/**
	 * Tell if the js scripts have been enqueued and prevent to do it twice.
	 *
	 * @var (bool)
	 */
	protected static $done_js  = false;
	/**
	 * ".min" suffix to add (or not) to the css/js file name.
	 *
	 * @var (string)
	 */
	protected static $suffix;
	/**
	 * Version to use for the css/js files.
	 *
	 * @var (string)
	 */
	protected static $version;


	/** Public methods ========================================================================== */

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
	 *                                  empty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
	 * @param (null|string) $capa       A WordPress capability or role. "null" = secupress_get_capability()
 	 */
	public function add( $message, $error_code = 'updated', $notice_id = false, $capa = null ) {
		if ( is_null( $capa ) ) {
			$capa = secupress_get_capability( false, 'notice' );
		}
		if ( false !== $notice_id ) {
			if ( $notice_id && self::is_dismissed( $notice_id ) ) {
				return;
			}
			// Add notices script.
			self::enqueue_script();
		}

		// Add notices style.
		self::enqueue_style();

		$error_code = 'error' === $error_code ? 'error' : 'updated';
		$notice_id  = $notice_id ? sanitize_title( $notice_id ) : $notice_id;

		if ( ! isset( $this->notices[ $error_code ] ) ) {
			$this->notices[ $error_code ] = [
				'permanent'      => [],
				'wp-dismissible' => [],
				'sp-dismissible' => [],
			];
		}

		if ( false === $notice_id ) {
			// The notice is not dismissible.
			$this->notices[ $error_code ]['permanent'][ $capa ][]                  = $message;
		} elseif ( $notice_id ) {
			// The notice is dismissible, with a custom ajax call.
			$this->notices[ $error_code ]['sp-dismissible'][ $capa ][ $notice_id ] = $message;
		} else { // Empty string case
			// The notice is dismissible.
			$this->notices[ $error_code ]['wp-dismissible'][ $capa ][]             = $message;
		}
	}


	/**
	 * Add a temporary admin notice.
	 *
	 * @since 1.0
	 * @since 1.3 Added $notice_id parameter.
	 *
	 * @param (string)      $message    The message to display in the notice.
	 * @param (string)      $error_code Like WordPress notices: "error" or "updated". Default is "updated".
	 * @param (string|bool) $notice_id  A unique identifier to tell id the notice is dismissible.
	 *                                  false: the notice is not dismissible.
	 *                                  string: the notice is dismissible and send an ajax call to store the "dismissed" state into a user meta to prevent it to popup again.
	 *                                  enpty string: meant for a one-shot use. The notice is dismissible but the "dismissed" state is not stored, it will popup again. This is the exact same behavior than the WordPress dismissible notices.
	 * @param (null|string) $capa       A WordPress capability or role. "null" = secupress_get_capability()
	 */
	public function add_temporary( $message, $error_code = 'updated', $notice_id = false, $capa = null ) {
		$error_code = 'error' === $error_code ? 'error' : 'updated';
		$notices    = secupress_get_transient( 'secupress-notices-' . get_current_user_id() );
		$notices    = is_array( $notices ) ? $notices : array();
		$notices[]  = compact( 'message', 'error_code', 'capa', 'notice_id' );

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


	/** Private methods ========================================================================= */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		self::$suffix  = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
		self::$version = self::$suffix ? SECUPRESS_VERSION : time();

		add_action( 'all_admin_notices',                   array( $this, 'print_notices' ), 20 );
		add_action( 'admin_footer',                        array( $this, 'print_notices' ), 20 );
		add_action( 'wp_ajax_secupress_dismiss-notice',    array( __CLASS__, 'dismiss_admin_ajax_cb' ) );
		add_action( 'admin_post_secupress_dismiss-notice', array( __CLASS__, 'dismiss_admin_ajax_cb' ) );
	}


	/**
	 * Enqueue JS scripts.
	 *
	 * @since 1.0
	 */
	public static function enqueue_script() {
		if ( self::$done_js ) {
			return;
		}
		if ( ! did_action( 'admin_enqueue_scripts' ) ) {
			add_action( 'admin_enqueue_scripts', __METHOD__ );
			return;
		}
		self::$done_js = true;

		wp_enqueue_script( 'secupress-notices', SECUPRESS_ADMIN_JS_URL . 'secupress-notices' . self::$suffix . '.js', array( 'jquery' ), self::$version, true );
		wp_localize_script( 'secupress-notices', 'SecuPressi18nNotices', array(
			'dismiss' => _x( 'Dismiss', 'verb', 'secupress' ),
			'nonce'   => wp_create_nonce( 'secupress-notices' ),
		) );
	}


	/**
	 * Enqueue CSS styles.
	 *
	 * @since 1.0
	 */
	public static function enqueue_style() {
		if ( self::$done_css ) {
			return;
		}
		if ( ! did_action( 'admin_enqueue_scripts' ) ) {
			add_action( 'admin_enqueue_scripts', __METHOD__ );
			return;
		}
		self::$done_css = true;

		wp_enqueue_style( 'secupress-notices', SECUPRESS_ADMIN_CSS_URL . 'secupress-notices' . self::$suffix . '.css', array(), self::$version );
	}


	/**
	 * Add notices added by `$this->add_temporary()`.
	 *
	 * @since 2.2.6 Get the CRON notifications too
	 * @since 1.3
	 * @see Was previously called `secupress_display_transient_notices()`.
	 */
	public function add_transient_notices() {
		$notices      = secupress_get_transient( 'secupress-notices-' . get_current_user_id(), [] );
		$notices_cron = secupress_get_transient( 'secupress-notices-0', [] ); // 0 = CRON user ID, WP default
		$notices      = array_merge( $notices, $notices_cron );

		if ( ! $notices ) {
			return;
		}

		delete_transient( 'secupress-notices-' . get_current_user_id() );
		delete_transient( 'secupress-notices-0' ); // CRON

		if ( is_array( $notices ) ) {
			foreach ( $notices as $notice ) {
				$notice_id = isset( $notice['notice_id'] ) ? $notice['notice_id'] : false;
				$this->add( $notice['message'], $notice['error_code'], $notice_id );
			}
		}
	}


	/**
	 * Display the notices.
	 *
	 * The notices are displayed by error code ("error" or "updated"), then by type (dismissible with state stored, dismissible like WP, not dismissible).
	 * All not dismissible ones are grouped into one notice. Same thing for the "dismissible like WP" ones.
	 * Only the "dismissible with state stored" are printed separately, so the user can dismiss some and not others.
	 *
	 * @since 2.2.6 Use $capa
	 * @since 1.0
	 */
	public function print_notices() {
		$this->add_transient_notices();

		if ( ! $this->notices ) {
			return;
		}		

		$referer = urlencode( esc_url_raw( secupress_get_current_url( 'raw' ) ) );

		foreach ( $this->notices as $error_code => $types ) {
			$types = array_filter( $types, 'count' );
			if ( ! $types ) {
				continue;
			}

			foreach ( $types as $type => $roles ) {
				foreach( $roles as $capa => $messages ) {
					if ( ! current_user_can( $capa ) ) {
						continue;
					}
					$plugin_name = SECUPRESS_PLUGIN_NAME . ( secupress_has_pro() && ! secupress_is_white_label() ? ' Pro' : '' );
					$label       = secupress_is_expert_mode() ? '' : '<label class="plugin-title">' . esc_html( $plugin_name ) . '</label>';
					$lab_class   = secupress_is_expert_mode() ? '' : ' has-plugin-title';
					if ( 'sp-dismissible' === $type ) {
						foreach ( $messages as $notice_id => $message ) {
							$button = admin_url( 'admin-post.php?action=secupress_dismiss-notice&notice_id=' . $notice_id . '&_wp_http_referer=' . $referer );
							$button = wp_nonce_url( $button, 'secupress-notices' );
							$button = '<a href="' . esc_url( $button ) . '" class="notice-dismiss"><span class="screen-reader-text">' . __( 'Dismiss', 'secupress' ) . '</span></a>';
							$message = strpos( $message, '<p>' ) === false && trim( $message ) ? '<p>' . $message . '</p>' : $message;
							?>
							<div class="<?php echo $error_code . $lab_class; ?> notice secupress-notice secupress-is-dismissible" data-id="<?php echo $notice_id; ?>">
								<?php echo $label; ?>
								<?php echo $message; ?>
								<?php echo $button; ?>
							</div>
							<?php
				    		unset( $this->notices[ $error_code ][ $type ][ $capa ][ $notice_id ] );
						}
					} elseif ( 'wp-dismissible' === $type ) {
						?>
						<div class="<?php echo $error_code . $lab_class; ?> notice secupress-notice secupress-is-dismissible">
							<?php echo $label; ?>
							<?php
							$message = implode( '<br class="separator"/>', $messages );
							echo strpos( $message, '<p>' ) === false ? '<p>' . $message . '</p>' : $message;
				    		unset( $this->notices[ $error_code ][ $type ] );
							?>
						</div>
						<?php
					} else {
						?>
						<div class="<?php echo $error_code . $lab_class; ?> notice secupress-notice">
							<?php echo $label; ?>
							<?php
							$message = implode( '<br class="separator"/>', $messages );
							echo strpos( $message, '<p>' ) === false ? '<p>' . $message . '</p>' : $message;
				    		unset( $this->notices[ $error_code ][ $type ] );
							?>
						</div>
						<?php
					}
				}
			}
		}
	}


	/**
	 * Ajax callback that stores the "dismissed" state.
	 *
	 * @since 2.2.6 Usage of the $capa param
	 * @since 1.0
	 */
	public static function dismiss_admin_ajax_cb() {
		if ( empty( $_REQUEST['notice_id'] ) ) { // WPCS: CSRF ok.
			wp_die( -1 );
		}
		if ( wp_doing_ajax() ) {
			secupress_check_admin_referer( 'secupress-notices' );
		} else {
			secupress_check_admin_referer( 'secupress-notices' );
		}

		$notice_id = $_REQUEST['notice_id'];
		$notice_id = $notice_id ? sanitize_title( $notice_id ) : $notice_id;

		/**
		 * @since 1.0
		 * @since 2.2.6 Deprecated filter
		 */
		if ( has_filter( 'secupress.notices.dismiss_capability' ) ) {
			_deprecated_hook( 'secupress.notices.dismiss_capability', '2.2.6', '(none)', 'A 4th parameter $capa has been added to secupress_add_notice()' );
		}

		if ( wp_doing_ajax() ) {
			if ( self::dismiss( $notice_id ) ) {
				wp_die( 1 );
			}
		} else {
			if ( self::dismiss( $notice_id ) ) {
				wp_safe_redirect( esc_url_raw( wp_get_referer() ) );
				die();
			}
		}

		if ( wp_doing_ajax() ) {
			wp_die( -1 );
		} else {
			secupress_admin_die();
		}
	}
}