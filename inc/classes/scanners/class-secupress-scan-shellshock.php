<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

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
	const VERSION = '1.1';


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
		$this->title = __( 'Check if your website is vulnerable to "<strong>Shellshock</strong>".', 'secupress' );
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
		$messages = array(
			// "good"
			0   => __( 'The server is not vulnerable to <strong>Shellshock</strong>.', 'secupress' ),
			1   => __( 'The protection against <strong>Shellshock</strong> has been activated. It won\'t fix the vulnerability (only your host can) but it will prevent an attacker to exploit it remotely.', 'secupress' ),
			// "warning"
			100 => sprintf(
				__( 'Unable to determine the status of the <strong>Shellshock</strong> flaw (%1$s). But you can activate the %2$s protection manually from the module %3$s.', 'secupress' ),
				'<em>CVE-2014-6271</em>',
				'<em>' . __( 'Block Bad User-Agents', 'secupress' ) . '</em>',
				'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_user-agents-header">' . __( 'Firewall', 'secupress' ) . '</a>'
			),
			101 => sprintf(
				__( 'Unable to determine the status of the <strong>Shellshock</strong> flaw (%1$s). But you can activate the %2$s protection manually from the module %3$s.', 'secupress' ),
				'<em>CVE-2014-7169</em>',
				'<em>' . __( 'Block Bad User-Agents', 'secupress' ) . '</em>',
				'<a target="_blank" href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-headers_user-agents-header">' . __( 'Firewall', 'secupress' ) . '</a>'
			),
			// "bad"
			200 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-6271</em>' ),
			201 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-7169</em>' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
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
		if ( 'WIN' === strtoupper( substr( PHP_OS, 0, 3 ) ) ) {
			// "good"
			$this->add_message( 0 );
			return parent::scan();
		}

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

		if ( 'error' === $output ) {
			// "warning"
			$this->add_message( 100 );
		} elseif ( false !== strpos( $output, 'VULNERABLE' ) ) {
			// "bad"
			$this->add_message( 200 );
		}

		// CVE-2014-7169.
		$test_date = date( 'Y' );
		$p         = proc_open( "rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir() );
		$output    = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
		proc_close( $p );

		if ( 'error' === $output ) {
			// "warning"
			$this->add_message( 101 );
		} elseif ( trim( $output ) === $test_date ) {
			// "bad"
			$this->add_message( 201 );
		}

		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

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
