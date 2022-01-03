<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Shellshock scan class.
 * Previously was part of `SecuPress_Scan_Common_Flaws`.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.1.4
 * @see http://plugins.svn.wordpress.org/shellshock-check/trunk/shellshock-check.php
 * @see https://www.shellshock.fr/
 */
class SecuPress_Scan_Shellshock extends SecuPress_Scan implements SecuPress_Scan_Interface {

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
	 * @since 1.1.4
	 */
	protected function init() {
		$this->title = __( 'Check if your server is vulnerable to <strong>Shellshock</strong>.', 'secupress' );
		$this->more  = __( '<strong>Shellshock</strong> is a critic vulnerability allowing an attacker to remotely execute malicious code on a server.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s in the %2$s module.', 'secupress' ),
			'<em>' . __( 'Block Bad User-Agents', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_user-agents-header">' . __( 'Firewall', 'secupress' ) . '</a>'
		);
	}


	/**
	 * Get messages.
	 *
	 * @since 1.1.4
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		/** Translators: 1 is the name of a protection, 2 is the name of a module. */
		$activate_protection_message = sprintf( __( 'But you can activate the %1$s protection from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Bad User-Agents', 'secupress' ) . '</em>',
			'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_user-agents-header">' . __( 'Firewall', 'secupress' ) . '</a>'
		);

		$messages = array(
			// "good"
			0   => __( 'The server is not vulnerable to <strong>Shellshock</strong>.', 'secupress' ),
			1   => __( 'The protection against <strong>Shellshock</strong> has been activated. It won’t fix the vulnerability (only your host can) but it will prevent an attacker to exploit it remotely.', 'secupress' ),
			// "warning"
			100 => sprintf( __( 'Unable to determine the status of the <strong>Shellshock</strong> flaw (%s).', 'secupress' ), '<em>CVE-2014-6271</em>' ) . ' ' . $activate_protection_message,
			101 => sprintf( __( 'Unable to determine the status of the <strong>Shellshock</strong> flaw (%s).', 'secupress' ), '<em>CVE-2014-7169</em>' ) . ' ' . $activate_protection_message,
			102 => __( 'Unable to determine the status of the <strong>Shellshock</strong> flaw.', 'secupress' ) . ' ' . $activate_protection_message,
			// "bad"
			200 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-6271</em>' ),
			201 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-7169</em>' ),
			202 => __( 'The server may be vulnerable to <strong>Shellshock</strong>.', 'secupress' ),
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
		return __( 'https://docs.secupress.me/article/115-shellshock-scan', 'secupress' );
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.1.4
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		if ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) ) {
			// "good"
			$this->add_message( 0 );
			return parent::scan();
		}

		if ( ! secupress_is_function_disabled( 'proc_open' ) ) {
			// Scan with `proc_open()`.
			$env  = array( 'SHELL_SHOCK_TEST' => '() { :;}; echo VULNERABLE' );
			$desc = array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			);

			// CVE-2014-6271.
			$p      = proc_open( 'bash -c "echo Test"', $desc, $pipes, null, $env );
			$output = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
			proc_close( $p );

			if ( false !== strpos( $output, 'VULNERABLE' ) ) {
				// "bad"
				$this->add_message( 200 );
			}

			// CVE-2014-7169.
			$test_date = date( 'Y' );
			$p         = proc_open( "rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir() );
			$output    = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
			proc_close( $p );

			if ( trim( $output ) === $test_date ) {
				// "bad"
				$this->add_message( 201 );
			}
		} else {
			// Scan by altering the User-Agent.
			$request_args = $this->get_default_request_args();
			$request_args['user-agent'] = '() { :;}; echo VULNERABLE';
			$response     = wp_remote_get( add_query_arg( secupress_generate_key( 6 ), secupress_generate_key( 8 ), user_trailingslashit( home_url() ) ), $request_args );

			if ( ! is_wp_error( $response ) ) {

				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					// "bad"
					$this->add_message( 202 );
				} else {
					// "good"
					$this->add_message( 0 );
				}
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
	 * @since 1.1.4
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		// Activate.
		secupress_activate_submodule( 'firewall', 'user-agents-header' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
