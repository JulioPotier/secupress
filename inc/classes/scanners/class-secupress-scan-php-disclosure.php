<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PHP Disclosure scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_PHP_Disclosure extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'low';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses the PHP modules <em>(know as PHP Easter Egg)</em>.', 'secupress' );
		self::$more  = __( 'PHP contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered when a remote attacker makes certain HTTP requests with crafted arguments, which will disclose PHP version and another sensitive information resulting in a loss of confidentiality.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$nginx_rules = "location / {\n\t" . 'if ( $query_string ~* "\=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" ) {' . "\n\t\treturn 403;\n\t}\n}";
		$messages = array(
			// good
			0   => __( 'Your site does not reveal the PHP modules.', 'secupress' ),
			1   => sprintf( __( 'Your %s file has been successfully edited.', 'secupress' ), '<code>.htaccess</code>' ),
			// warning
			100 => sprintf( __( 'Unable to determine status of %s.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// bad
			200 => sprintf( __( '%s should not be accessible to anyone.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// cantfix
			/* translators: 1 si a file name, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the sensitive information disclosure cannot be fixed automatically but you can do it yourself by adding the following code into your %1$s file: %2$s.', 'secupress' ), '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => sprintf( __( 'You run an IIS7 system, I cannot fix this sensitive information disclosure but you can do it yourself with the following code: %s.', 'secupress' ), '<code>(add IIS code here)</code>' ), //// iis7_url_rewrite_rules ?
			302 => __( 'Your server runs a non recognized system. The sensitive information disclosure cannot be fixed automatically.', 'secupress' ),
			303 => __( 'Your %1$s file is not writable. Please add the following lines to the file: %2$s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// http://osvdb.org/12184
		$response = wp_remote_get( user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000', array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$body = wp_remote_retrieve_body( $response );

			if ( strpos( $body, '<h1>PHP Credits</h1>' ) > 0 && strpos( $body, '<title>phpinfo()</title>' ) > 0 ) {
				// bad
				$this->add_message( 200 );
			}

		} else {
			// warning
			$this->add_message( 100 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_nginx, $is_iis7;

		// Not Apache system, bail out.
		if ( ! $is_apache ) {

			if ( $is_nginx ) {
				$this->add_fix_message( 300 );
			} elseif ( $is_iis7 ) {
				$this->add_fix_message( 301 ); //// iis7_url_rewrite_rules
			} else {
				$this->add_fix_message( 302 );
			}

			return parent::fix();
		}

		// Edit `.htaccess` file.
		$rules  = "<IfModule mod_rewrite.c>\n";
		$rules .= "    RewriteEngine on\n";
		$rules .= "    RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC]\n";
		$rules .= "    RewriteRule .* - [F]\n";
		$rules .= "</IfModule>";

		if ( secupress_write_htaccess( 'php_disclosure', $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 303, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress php_disclosure\n$rules\n# END SecuPress</pre>" ) );
		}

		return parent::fix();
	}
}
