<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Core Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Core_Update extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	 * Tells if the fix must occur after all other scans and fixes, while no other scan/fix is running.
	 *
	 * @var (bool)
	 */
	protected $delayed_fix = true;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your WordPress core is up to date.', 'secupress' );
		$this->more     = __( 'It’s very important to keep your WordPress installation up to date. If you cannot update for any reason, contact your hosting provider as soon as possible.', 'secupress' );
		$this->more_fix = __( 'Update your WordPress installation right away.', 'secupress' );
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
			0   => __( 'WordPress core is up to date.', 'secupress' ),
			1   => __( 'WordPress has been updated to version <strong>%s</strong>.', 'secupress' ),
			2   => '%s', // Already translated.
			// "bad".
			200 => __( 'WordPress core is <strong>not up to date</strong>.', 'secupress' ),
			// "cantfix"
			300 => '%s', // Already translated.
			301 => __( 'You have the latest version of WordPress.', 'secupress' ),
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
		return __( 'https://docs.secupress.me/article/95-wordpress-core-update-scan', 'secupress' );
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

		ob_start();

		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/update.php' );
		}

		wp_version_check();
		$core_update = get_preferred_from_update_core();
		$core_update = isset( $core_update->response ) && 'upgrade' === $core_update->response;

		ob_flush();

		if ( $core_update ) {
			// "bad"
			$this->add_message( 200 );
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
		ob_start();
		secupress_time_limit( 0 );

		$core    = get_preferred_from_update_core();
		$version = isset( $core->version ) ? $core->version : false;
		$locale  = isset( $core->locale )  ? $core->locale  : 'en_US';
		$result  = false;

		if ( $version ) {
			include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );

			$url       = 'update-core.php?action=do-core-upgrade';
			$nonce     = 'upgrade-core';
			$url_nonce = wp_nonce_url( $url, $nonce );
			$update    = find_core_update( $version, $locale );

			if ( $update ) {
				$allow_relaxed_file_ownership = isset( $update->new_files ) && ! $update->new_files;
				$credentials = request_filesystem_credentials( $url_nonce, '', false, ABSPATH, array( 'version', 'locale' ), $allow_relaxed_file_ownership );

				if ( WP_Filesystem( $credentials, ABSPATH, $allow_relaxed_file_ownership ) ) {

					// Remove the WP upgrade process for translation since it will output data, use our own based on core but using a silent upgrade.
					remove_action( 'upgrader_process_complete', array( 'Language_Pack_Upgrader', 'async_upgrade' ), 20 );
					add_action( 'upgrader_process_complete', 'secupress_async_upgrades', 20 );

					$skin     = new Automatic_Upgrader_Skin( compact( 'nonce', 'url' ) );
					$upgrader = new Core_Upgrader( $skin );
					$result   = $upgrader->upgrade( $update, array(
						'allow_relaxed_file_ownership' => $allow_relaxed_file_ownership,
					) );
				}
			}
		}

		ob_end_clean();

		if ( is_string( $result ) ) {

			$this->add_fix_message( 1, array( $result ) );

		} elseif ( false === $result ) {

			$this->add_fix_message( 301 );

		} else {
			$errors = reset( $result->errors );
			$code   = isset( $errors['up_to_date'] ) ? 2 : 300;
			$this->add_fix_message( $code, array( reset( $errors ) ) );
		}

		return parent::fix();
	}
}
