<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Bad URL Access scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Bad_URL_Access extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
		global $is_apache, $is_nginx, $is_iis7;

		$this->title    = __( 'Check if any of your WordPress files disclose your site’s internal path.', 'secupress' );
		$this->more     = __( 'When an attacker wants to hack into a WordPress site, they will search for all available informations. The goal is to find something useful that will help him penetrate your site. Don’t let them easily find any informations.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<strong>' . __( 'Bad URL Access', 'secupress' ) . '</strong>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) ) . '#row-content-protect_bad-url-access">' . __( 'Sensitive Data', 'secupress' ) . '</a>'
		);

		if ( ! $is_apache && ! $is_nginx && ! $is_iis7 ) {
			$this->more_fix = static::get_messages( 301 );
			$this->fixable  = false;
			return;
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
		global $is_apache;

		$config_file = $is_apache ? '.htaccess' : 'web.config';

		$messages = array(
			// "good"
			0   => __( 'Your site does not reveal your site’s internal path.', 'secupress' ),
			/** Translators: %s is a file name. */
			1   => sprintf( __( 'Rules preventing disclosure of your site’s internal path disclosure have been added to your %s file.', 'secupress' ), "<code>$config_file</code>" ),
			// "warning"
			100 => _n_noop(
				/** Translators: %s is a URL or a list of URLs. */
				'Unable to determine if %s is accessible.',
				'Unable to determine if %s are accessible.',
				'secupress'
			),
			101 => sprintf(
				/** Translators: 1 is the name of a protection, 2 is the name of a module. */
				__( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
				'<strong>' . __( 'Bad URL Access', 'secupress' ) . '</strong>',
				'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'sensitive-data' ) ) . '#row-content-protect_bad-url-access">' . __( 'Sensitive Data', 'secupress' ) . '</a>'
			),
			// "bad"
			/** Translators: %s is a URL, or a list of URLs. */
			200 => _n_noop( '%s should not be accessible by anyone.', '%s should not be accessible by anyone.', 'secupress' ),
			// "cantfix"
			/** Translators: 1 is a file name, 2 is some code. */
			300 => sprintf( __( 'Your server runs <strong>Nginx</strong>, the files that disclose your site’s internal path cannot be protected automatically but you can do it yourself by adding the following code to your %1$s file: %2$s', 'secupress' ), '<code>nginx.conf</code>', '%s' ),
			301 => __( 'Your server runs an unrecognized system. The files that disclose your site’s internal path cannot be protected automatically.', 'secupress' ),
			/** Translators: 1 is a file name, 2 is some code. */
			302 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ), "<code>$config_file</code>", '%s' ),
			/** Translators: 1 is a file name, 2 is a folder path (kind of), 3 is some code. */
			303 => sprintf( __( 'Your %1$s file is not writable. Please add the following lines inside the tags hierarchy %2$s (create it if does not exist): %3$s', 'secupress' ), "<code>$config_file</code>", '%1$s', '%2$s' ),
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
		return __( 'https://docs.secupress.me/article/107-sensitive-files-access-scan', 'secupress' );
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

		// Avoid plugin's hooks.
		remove_all_filters( 'site_url' );
		remove_all_filters( 'includes_url' );
		remove_all_filters( 'admin_url' );
		remove_all_filters( 'home_url' );

		$bads     = array();
		$warnings = array();
		$urls     = array(
			home_url( 'php.ini' ),
			site_url( 'wp-config.php' ),
			admin_url( 'install.php' ),
			admin_url( 'network/menu.php' ),
			admin_url( 'user/menu.php' ),
			includes_url( 'admin-bar.php' ),
		);

		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, $this->get_default_request_args() );

			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$bads[] = "<code>$url</code>";
			}
		}

		if ( $bads ) {
			// "bad"
			$this->add_message( 200, array( count( $bads ), $bads ) );

			if ( ! $this->fixable ) {
				$this->add_pre_fix_message( 301 );
			}
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
		global $is_apache, $is_nginx, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		} elseif ( $is_nginx ) {
			$this->fix_nginx();
		}

		// "good"
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/**
	 * Fix for Apache system.
	 *
	 * @since 1.0
	 */
	protected function fix_apache() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'sensitive-data', 'bad-url-access' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'apache_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			// "cantfix"
			$this->add_fix_message( 302, array( $rules ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1 );
	}


	/**
	 * Fix for IIS7 system.
	 *
	 * @since 1.0
	 */
	protected function fix_iis7() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'sensitive-data', 'bad-url-access' );

		// Got error?
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;

		if ( $last_error && 'general' === $last_error['setting'] && 'iis7_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			$path  = static::get_code_tag_from_error( $last_error, 'secupress-iis7-path' );
			// "cantfix"
			$this->add_fix_message( 303, array( $path, $rules ) );
			array_pop( $wp_settings_errors );
			return;
		}

		// "good"
		$this->add_fix_message( 1 );
	}


	/**
	 * Fix for nginx system.
	 *
	 * @since 1.0
	 */
	protected function fix_nginx() {
		global $wp_settings_errors;

		secupress_activate_submodule( 'sensitive-data', 'bad-url-access' );

		// Get the error.
		$last_error = is_array( $wp_settings_errors ) && $wp_settings_errors ? end( $wp_settings_errors ) : false;
		$rules      = '<code>Error</code>';

		if ( $last_error && 'general' === $last_error['setting'] && 'nginx_manual_edit' === $last_error['code'] ) {
			$rules = static::get_rules_from_error( $last_error );
			array_pop( $wp_settings_errors );
		}

		// "cantfix"
		$this->add_fix_message( 300, array( $rules ) );
	}
}
