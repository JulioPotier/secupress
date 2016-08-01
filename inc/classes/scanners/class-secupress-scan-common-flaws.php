<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Common Flaws scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_Common_Flaws extends SecuPress_Scan implements SecuPress_Scan_Interface {

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


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title = __( 'Check if your website can easily be the target of common flaws.', 'secupress' );
		$this->more  = __( 'Every year new flaws are discovered. You have to be sure that your website cannot be a target.', 'secupress' );
		$this->more_fix = sprintf(
			__( 'Activate the option %1$s from the module %2$s.', 'secupress' ),
			'<em>' . __( 'Block Bad Contents', 'secupress' ) . '</em>',
			'<a href="' . esc_url( secupress_admin_url( 'modules', 'firewall' ) ) . '#row-bbq-url-content_bad-contents">' . __( 'Firewall', 'secupress' ) . '</a>'
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
			0   => _n_noop( '%d common flaws tested.', '%d common flaws tested.', 'secupress' ),
			1   => __( 'Protection activated', 'secupress' ),
			// "warning"
			100 => __( 'Unable to determine if your homepage can be the target of common flaws.', 'secupress' ),
			101 => sprintf( __( 'Unable to determine status of <strong>Shellshock</strong> flaw (%s).', 'secupress' ), '<em>CVE-2014-6271</em>' ),
			102 => sprintf( __( 'Unable to determine status of <strong>Shellshock</strong> flaw (%s).', 'secupress' ), '<em>CVE-2014-7169</em>' ),
			// "bad"
			200 => __( 'Your website pages should be <strong>different</strong> for each reload.', 'secupress' ),
			201 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-6271</em>' ),
			202 => sprintf( __( 'The server appears to be vulnerable to <strong>Shellshock</strong> (%s).', 'secupress' ), '<em>CVE-2014-7169</em>' ),
			203 => __( 'Your website should block <strong>malicious requests</strong>.', 'secupress' ),
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
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		$nbr_tests = 0;

		/**
		 * Shellshock.
		 *
		 * @see http://plugins.svn.wordpress.org/shellshock-check/trunk/shellshock-check.php
		 * @see https://www.shellshock.fr/
		 */
		if ( 'WIN' !== strtoupper( substr( PHP_OS, 0, 3 ) ) ) {
			++$nbr_tests;

			$env = array( 'SHELL_SHOCK_TEST' => '() { :;}; echo VULNERABLE' );

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
				$this->add_message( 101 );
			} elseif ( false !== strpos( $output, 'VULNERABLE' ) ) {
				// "bad"
				$this->add_message( 201 );
			}

			// CVE-2014-7169.
			$test_date = date( 'Y' );
			$p         = proc_open( "rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir() );
			$output    = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
			proc_close( $p );

			if ( 'error' === $output ) {
				// "warning"
				$this->add_message( 102 );
			} elseif ( trim( $output ) === $test_date ) {
				// "bad"
				$this->add_message( 202 );
			}
		}

		/**
		 * `wp-config.php` access.
		 */
		++$nbr_tests;
		$response = wp_remote_get( add_query_arg( time(), 'wp-config.php', user_trailingslashit( home_url() ) ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// "bad"
				$this->add_message( 203 );
			}
		} else {
			// "warning"
			$this->add_message( 100 );
		}

		// "good"
		$this->maybe_set_status( 0, array( $nbr_tests, $nbr_tests ) );

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
		// Activate.
		secupress_activate_submodule( 'firewall', 'bad-url-contents' );

		// "good"
		$this->add_fix_message( 1 );

		return parent::fix();
	}
}
